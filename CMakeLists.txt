cmake_minimum_required(VERSION 3.26)
project(openssl_pkcs7 C)

set(CMAKE_C_STANDARD 11)
find_package(OpenSSL REQUIRED)
if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "Where is OpenSSL bitch?!")
endif()
link_libraries(${OPENSSL_LIBRARIES})
add_library(openssl_pkcs7 SHARED openssl_pkcs7.c)
set_target_properties(openssl_pkcs7 PROPERTIES PUBLIC_HEADER "openssl_pkcs7.h")

install(TARGETS openssl_pkcs7
        LIBRARY
        DESTINATION lib
        COMPONENT openssl_pkcs
        PUBLIC_HEADER
        DESTINATION include
        COMPONENT openssl_pkcs
)