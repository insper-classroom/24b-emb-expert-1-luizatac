#include <stdio.h>
#include <string.h>
#include <FreeRTOS.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include <task.h>
#include <semphr.h>
#include <queue.h>
#include "hardware/gpio.h"
#include "hardware/adc.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#define WIFI_SSID "Gabriel's Galaxy S21 5G"
#define WIFI_PASSWORD "rnfa4694"
#define SERVER_IP "192.168.65.182"

#define TCP_PORT 5000
#define DEBUG_printf printf
#define BUF_SIZE 2048

#define TEST_ITERATIONS 10
#define POLL_TIME_S 5


QueueHandle_t xQueueAdc;

typedef struct adc {
    int axis;
    int val;
} adc_t;


#if 0
static void dump_bytes(const uint8_t *bptr, uint32_t len) {
    unsigned int i = 0;

    printf("dump_bytes %d", len);
    for (i = 0; i < len;) {
        if ((i & 0x0f) == 0) {
            printf("\n");
        } else if ((i & 0x07) == 0) {
            printf(" ");
        }
        printf("%02x ", bptr[i++]);
    }
    printf("\n");
}
#define DUMP_BYTES dump_bytes
#else
#define DUMP_BYTES(A, B)
#endif

typedef struct TCP_CLIENT_T_ {
    struct tcp_pcb *tcp_pcb;
    ip_addr_t remote_addr;
    uint8_t buffer[BUF_SIZE];
    int buffer_len;
    int sent_len;
    bool complete;
    int run_count;
    bool connected;
} TCP_CLIENT_T;

static err_t tcp_client_close(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    if (state == NULL) {
        // Retorna imediatamente se state for NULL
        return ERR_OK;
    }
    err_t err = ERR_OK;
    if (state->tcp_pcb != NULL) {
        tcp_arg(state->tcp_pcb, NULL);
        tcp_poll(state->tcp_pcb, NULL, 0);
        tcp_sent(state->tcp_pcb, NULL);
        tcp_recv(state->tcp_pcb, NULL);
        tcp_err(state->tcp_pcb, NULL);
        err = tcp_close(state->tcp_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(state->tcp_pcb);
            err = ERR_ABRT;
        }
        state->tcp_pcb = NULL;
    }
    return err;
}

// Called with results of operation
static err_t tcp_result(void *arg, int status) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    if (status == 0) {
        DEBUG_printf("test success\n");
    } else {
        DEBUG_printf("test failed %d\n", status);
    }
    state->complete = true;
    return tcp_client_close(arg);
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    DEBUG_printf("tcp_client_sent %u\n", len);
    state->sent_len += len;

    if (state->sent_len >= BUF_SIZE) {

        state->run_count++;
        if (state->run_count >= TEST_ITERATIONS) {
            tcp_result(arg, 0);
            return ERR_OK;
        }

        // We should receive a new buffer from the server
        state->buffer_len = 0;
        state->sent_len = 0;
        DEBUG_printf("Waiting for buffer from server\n");
    }

    return ERR_OK;
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    if (err != ERR_OK) {
        printf("connect failed %d\n", err);
        return tcp_result(arg, err);
    }
    state->connected = true;
    DEBUG_printf("Waiting for buffer from server\n");
    return ERR_OK;
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_client_poll\n");
    return tcp_result(arg, -1); // no response is an error?
}

static void tcp_client_err(void *arg, err_t err) {
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err %d\n", err);
        tcp_result(arg, err);
    }
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    if (!p) {
        return tcp_result(arg, -1);
    }
    // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
    // can use this method to cause an assertion in debug mode, if this method is called when
    // cyw43_arch_lwip_begin IS needed
    cyw43_arch_lwip_check();
    if (p->tot_len > 0) {
        DEBUG_printf("recv %d err %d\n", p->tot_len, err);
        for (struct pbuf *q = p; q != NULL; q = q->next) {
            DUMP_BYTES(q->payload, q->len);
        }
        // Receive the buffer
        const uint16_t buffer_left = BUF_SIZE - state->buffer_len;
        state->buffer_len += pbuf_copy_partial(p, state->buffer + state->buffer_len,
                                               p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
        tcp_recved(tpcb, p->tot_len);
    }
    pbuf_free(p);

    // If we have received the whole buffer, send it back to the server
    if (state->buffer_len == BUF_SIZE) {
        DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t error = tcp_write(tpcb, state->buffer, state->buffer_len, TCP_WRITE_FLAG_COPY);
        if (error != ERR_OK) {
            DEBUG_printf("Failed to write data %d\n", err);
            return tcp_result(arg, -1);
        }
    }
    return ERR_OK;
}

static bool tcp_client_open(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T *)arg;
    DEBUG_printf("Connecting to %s port %u\n", ip4addr_ntoa(&state->remote_addr), TCP_PORT);
    state->tcp_pcb = tcp_new_ip_type(IP_GET_TYPE(&state->remote_addr));
    if (!state->tcp_pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    tcp_arg(state->tcp_pcb, state);
    tcp_poll(state->tcp_pcb, tcp_client_poll, POLL_TIME_S * 2);
    tcp_sent(state->tcp_pcb, tcp_client_sent);
    tcp_recv(state->tcp_pcb, tcp_client_recv);
    tcp_err(state->tcp_pcb, tcp_client_err);

    state->buffer_len = 0;

    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();
    err_t err = tcp_connect(state->tcp_pcb, &state->remote_addr, TCP_PORT, tcp_client_connected);
    cyw43_arch_lwip_end();

    return err == ERR_OK;
}

// Perform initialisation
static TCP_CLIENT_T *tcp_client_init(void) {
    TCP_CLIENT_T *state = calloc(1, sizeof(TCP_CLIENT_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    ip4addr_aton(SERVER_IP, &state->remote_addr);
    return state;
}



void x_task(void *p) {
    adc_init();
    adc_gpio_init(26);

    adc_t data;
    int window_x[5] = {0};
    

    while (1) {
        adc_select_input(0); 
        data.val = adc_read();

        window_x[4] = window_x[3];
        window_x[3] = window_x[2];
        window_x[2] = window_x[1];
        window_x[1] = window_x[0];
        window_x[0] = data.val;

        int soma_dados=window_x[4]+ window_x[3]+window_x[2]+ window_x[1] + window_x[0];
        int average = soma_dados / 5;

        data.val=average;
        data.axis =0;
        xQueueSend(xQueueAdc, &data, 0);

        vTaskDelay(pdMS_TO_TICKS(50));
        
    }
}
void y_task(void *p) {
    adc_init();
    adc_gpio_init(27);

    
    adc_t data;
    int window_y[5] = {0};
   

    while (1) {
        adc_select_input(1); 
        data.val = adc_read();

        window_y[4] = window_y[3];
        window_y[3] = window_y[2];
        window_y[2] = window_y[1];
        window_y[1] = window_y[0];
        window_y[0] = data.val;

        int soma_dados=window_y[4]+ window_y[3]+window_y[2]+ window_y[1] + window_y[0];
        int average = soma_dados / 5;

        data.val=average;
        data.axis = 1;

        xQueueSend(xQueueAdc, &data, 0);

        vTaskDelay(pdMS_TO_TICKS(50));
        
    }
}



void wifi_task(void *p) {

    // Contador
    adc_t data;
  

    while (1) {

        if (xQueueReceive(xQueueAdc, &data, portMAX_DELAY)== pdTRUE){

            int valor = ((data.val -2047)* 255)/ 2047;

            

            
            char payload_content[64];
            int payload_length = 0;
            payload_length = sprintf(payload_content, "value=%d",valor);

            const char *http_request = "POST /post_data HTTP/1.1\r\n"
                                    "Content-Type: application/x-www-form-urlencoded\r\n"
                                    "Content-Length: %d\r\n"
                                    "\r\n"
                                    "%s";

            char request_new[255];
            sprintf(request_new, http_request, payload_length, payload_content);
            printf("%s\n", request_new);

            TCP_CLIENT_T *state = tcp_client_init();

            if (state && tcp_client_open(state)) {
                printf("SOCKET: Conectado ao servidor\n");
                cyw43_arch_lwip_begin();
                int err = tcp_write(state->tcp_pcb, request_new, strlen(request_new), 0);
                cyw43_arch_lwip_end();

                if (err != ERR_OK) {
                    printf("TCP: Falha ao enviar dados\n");
                    printf("TCP: Servidor está rodando? Porta e IP corretos?\n");
                    printf("\nerrno: %d \n", err);
                } else {
                    printf("TCP: Dados enviados com sucesso\n");
                }

                vTaskDelay(pdMS_TO_TICKS(500));
            } else {
                printf("SOCKET: Falha ao conectar ao servidor\n");
                printf("SOCKET: Verifique IP, porta e rede wifi\n");
            }

            tcp_client_close(state);
            free(state);
            }
    }
}

int main() {
    char sIP[] = "xxx.xxx.xxx.xxx";

    stdio_init_all();

    // Inicializa o módulo Wi-Fi
    if (cyw43_arch_init()) {
        printf("Falha na inicialização do Wi-Fi\n");
        return -1;
    }
    printf("Wi-Fi inicializado com sucesso\n");

    // Ativa o modo de estação (STA)
    cyw43_arch_enable_sta_mode();

    // Tenta conectar ao Wi-Fi
    int result = cyw43_arch_wifi_connect_blocking(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_MIXED_PSK);

    // Verifica o resultado da conexão
    if (result) {
        printf("Conexão Wi-Fi falhou\n");
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0); // Desliga o LED
        return -1;
    }

    // Se conectado com sucesso, acende o LED
    printf("Conectado ao Wi-Fi com sucesso\n");
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1); // Acende o LED
    strcpy(sIP, ip4addr_ntoa(netif_ip4_addr(netif_list)));
    printf("Conectado, IP %s\n", sIP);


    xQueueAdc = xQueueCreate(32, sizeof(adc_t));
    xTaskCreate(wifi_task, "wifi task", 4095, NULL, 1, NULL);
    xTaskCreate(x_task, "X_task ", 4096, NULL, 1, NULL);
    xTaskCreate( y_task, "Y_task ", 4096, NULL, 1, NULL);

    vTaskStartScheduler();

    // Mantém o programa rodando
    while (true)
        ;
}