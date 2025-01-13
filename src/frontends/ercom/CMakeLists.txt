cmake_minimum_required(VERSION 3.10)  # Or a suitable minimum version

project(CryptosmartVPN)

set(SOURCES
        src/main.c
        src/cryptosmartvpn.c
)

set(HEADERS
        include/cryptosmartvpn.h
)

add_executable(cryptosmartvpn ${SOURCES})

target_include_directories(cryptosmartvpn PUBLIC include/)
