#include "openssl_pkcs7.h"

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>     /* X509_PURPOSE_ANY */
#include <openssl/x509_vfy.h>

#include <openssl/cms.h>
#include <openssl/pem.h>

int verify_pkcs7(void *ca, size_t ca_len, void *signature, size_t signature_len, void *data, size_t data_len) {
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;

    int ret = 0;

    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();

    st = X509_STORE_new();

    tbio = BIO_new_mem_buf(ca, ca_len);

    while ((cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) {
        if (!X509_STORE_add_cert(st, cacert)) {
            fprintf(stderr, "X509_STORE_add_cert FAILED\n");
            goto err;
        }
        X509_free(cacert);
    }

    in = BIO_new_mem_buf(signature, signature_len);

    if (!in) {
        goto err;
    }

    cont = BIO_new_mem_buf(data, data_len);

    if (!cont) {
        goto err;
    }

    p7 = d2i_PKCS7_bio(in, NULL);
    if (!PKCS7_verify(p7, NULL, st, cont, NULL, 0)){
        goto err;
    }

    ret = 1;

    err:

    if (ret == 0) {
        ERR_print_errors_fp(stderr);
    }

    X509_free(cacert);
    PKCS7_free(p7);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    BIO_free(cont);
    return ret;
}

char * pkcs7_attr(const void *signature, const int signature_len, const int attr){
    PKCS7 *p7 = NULL;
    BIO *in = NULL;
    int ret = 0;
    char *val = NULL;

    in = BIO_new_mem_buf(signature, signature_len);

    if (!in) {
        goto err;
    }
    p7 = d2i_PKCS7_bio(in, NULL);

    STACK_OF(PKCS7_SIGNER_INFO) *info = PKCS7_get_signer_info(p7);
    PKCS7_SIGNER_INFO *si = NULL;
    X509_NAME *subject						= NULL;
    int position							= 0;
    X509_NAME_ENTRY *entry					= NULL;
    ASN1_STRING *asn1Data					= NULL;
    unsigned char *entryString				= NULL;
    while((si = sk_PKCS7_SIGNER_INFO_pop(info))){
        X509 *userCert = PKCS7_cert_from_signer_info(p7, si);
        if(!((subject = X509_get_subject_name(userCert))) ||
           !((position = X509_NAME_get_index_by_NID(subject,attr, -1))) ||
           !((entry = X509_NAME_get_entry(subject, position))) ||
           ((asn1Data = X509_NAME_ENTRY_get_data(entry))))
        {
            char *s = (char *) ASN1_STRING_get0_data(asn1Data);
            val = strdup(s);
            ASN1_STRING_free(asn1Data);
            X509_NAME_ENTRY_free(entry);
            X509_NAME_free(subject);
        }
        X509_free(userCert);
        PKCS7_SIGNER_INFO_free(si);
    }

    PKCS7_free(p7);
    BIO_free(in);
    if(val == NULL){
        val = strdup("");
    }
    return val;
}
