cmake_minimum_required(VERSION 3.10)  # Or a suitable minimum version

project(CryptosmartVPN)

set(STRONGSWAN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../)

set(SOURCES
        src/main.c
        src/cryptosmartvpn.c
)

set(HEADERS
        include/cryptosmartvpn.h
)


add_executable(cryptosmartvpn ${LIBS} ${SOURCES})

target_include_directories(cryptosmartvpn PUBLIC include/)

target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/.libs/libstrongswan.so)
target_include_directories(cryptosmartvpn PRIVATE ${STRONGSWAN_DIR}/libstrongswan/)

#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/.libs/libstrongswan.so)
#target_include_directories(cryptosmartvpn PRIVATE ${STRONGSWAN_DIR}/libstrongswan/)

#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libipsec/.libs/libipsec.so)
target_include_directories(cryptosmartvpn PRIVATE ${STRONGSWAN_DIR}/libipsec/)

target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libcharon/.libs/libcharon.so)
target_include_directories(cryptosmartvpn PRIVATE ${STRONGSWAN_DIR}/libcharon/)

#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/pkcs1/.libs/libstrongswan-pkcs1.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/x509/.libs/libstrongswan-x509.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/openssl/.libs/libstrongswan-openssl.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/pem/.libs/libstrongswan-pem.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/pubkey/.libs/libstrongswan-pubkey.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libstrongswan/plugins/nonce/.libs/libstrongswan-nonce.a)

#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libcharon/plugins/socket_default/.libs/libstrongswan-socket-default.a)
#target_link_libraries(cryptosmartvpn ${STRONGSWAN_DIR}/libcharon/plugins/kernel_libipsec/.libs/libstrongswan-kernel-libipsec.a)

# For config.h
target_include_directories(cryptosmartvpn PRIVATE ${STRONGSWAN_DIR}/../)
