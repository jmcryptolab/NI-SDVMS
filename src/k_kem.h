#ifndef K_KEM_H
#define K_KEM_H

#include <stddef.h>
#include <stdint.h>

#define KYBER_PUBLICKEYBYTES 800
#define KYBER_SECRETKEYBYTES 1632
#define KYBER_CIPHERTEXTBYTES 768
#define KYBER_SSBYTES 32

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
