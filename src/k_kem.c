#include "k_kem.h"
#include <stdlib.h>

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    for (size_t i = 0; i < KYBER_PUBLICKEYBYTES; i++) pk[i] = rand() % 256;
    for (size_t i = 0; i < KYBER_SECRETKEYBYTES; i++) sk[i] = rand() % 256;
    return 0;
}

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    for (size_t i = 0; i < KYBER_CIPHERTEXTBYTES; i++) ct[i] = rand() % 256;
    for (size_t i = 0; i < KYBER_SSBYTES; i++) ss[i] = rand() % 256;
    return 0;
}

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    for (size_t i = 0; i < KYBER_SSBYTES; i++) ss[i] = rand() % 256;
    return 0;
}
