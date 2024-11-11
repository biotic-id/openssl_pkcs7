#ifndef OPENSSL_PKCS_OPENSSL_PKCS7_H
#define OPENSSL_PKCS_OPENSSL_PKCS7_H

#include <stddef.h>
#include <openssl/objects.h>
#include <stdlib.h>

int verify_pkcs7(void *ca, size_t ca_len, void *signature, size_t signature_len, void *data, size_t data_len);
char * pkcs7_attr(const void *signature, const int signature_len, const int attr);

#endif //OPENSSL_PKCS_OPENSSL_PKCS7_H
