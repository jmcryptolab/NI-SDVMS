#ifndef D_SIGN_H
#define D_SIGN_H

#include <stddef.h>
#include <stdint.h>

#define MAX_MSG_LENGTH 1024
#define CRYPTO_PUBLICKEYBYTES 1472
#define CRYPTO_SECRETKEYBYTES 3504
#define CRYPTO_BYTES 2701

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);
#endif
