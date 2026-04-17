cmake_minimum_required(VERSION 3.22.1)

project("aran-secure")

add_library(
        aran-secure
        SHARED
        rasp_core_engine.cpp
        aran-core.cpp
        aran_genesis.cpp
        aran_pin_validator.cpp
        anti_frida.cpp
        advanced_anti_frida.cpp
        rasp_defense.cpp
        advanced_rasp_defense.cpp
)

# Use Android system log library
find_library(
        log-lib
        log
)

target_link_libraries(
        aran-secure
        ${log-lib}
)
