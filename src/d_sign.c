#include "d_sign.h"
#include <string.h>
#include <stdlib.h>

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) pk[i] = rand() % 256;
    for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) sk[i] = rand() % 256;
    return 0;
}

int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk) {
    memcpy(sm, m, mlen);  // Copy message as part of signature
    for (size_t i = 0; i < CRYPTO_BYTES; i++) sm[mlen + i] = rand() % 256;
    *smlen = mlen + CRYPTO_BYTES;
    return 0;
}
