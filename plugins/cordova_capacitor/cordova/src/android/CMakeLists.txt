cmake_minimum_required(VERSION 3.22.1)
project("aran_rasp")

# ============================================
# CMAKE CONFIGURATION FOR ANDROID NATIVE LIBRARY
# ============================================

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================
# COMPILER FLAGS FOR SECURITY AND OBFUSCATION
# ============================================

# Symbol hiding
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

# Optimization flags for release
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Strip symbols
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--strip-all")

# ============================================
# SOURCE FILES
# ============================================

# Include the universal RASP core
set(RASP_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../universal_rasp_core")

if(EXISTS "${RASP_CORE_DIR}")
    set(SOURCES
        ${RASP_CORE_DIR}/universal_rasp_core.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/android_jni_bridge.cpp
    )
else()
    message(WARNING "Universal RASP core not found, using stub implementation")
    set(SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/android_jni_bridge.cpp
    )
endif()

# ============================================
# NATIVE LIBRARY
# ============================================

add_library(aran_rasp SHARED ${SOURCES})

# ============================================
# INCLUDE DIRECTORIES
# ============================================

target_include_directories(aran_rasp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RASP_CORE_DIR}
)

# ============================================
# LINKER FLAGS
# ============================================

target_link_libraries(aran_rasp
    log
    android
)

# ============================================
# POST-BUILD SYMBOL STRIPPING
# ============================================

add_custom_command(TARGET aran_rasp POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-unneeded libaran_rasp.so
    COMMENT "Stripping symbols from libaran_rasp.so"
)
