add_executable(main main.c)

# pull in common dependencies
target_link_libraries(main
                      pico_stdlib
                      pico_cyw43_arch_lwip_threadsafe_background
                      hardware_adc
                      freertos
                      )

target_include_directories(main
                           PRIVATE ${CMAKE_CURRENT_LIST_DIR})

# substituir pico_cyw43_arch_none por pico_cyw43_arch_lwip_threadsafe_background

# create map/bin/hex/uf2 file etc.
pico_add_extra_outputs(main)
