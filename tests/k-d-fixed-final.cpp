
#include <iostream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "d_randombytes.h"
#include "d_sign.h"
#include "k_kem.h"

using namespace std;
using namespace std::chrono;

#define NUM_SIGNERS 1024
#define MAX_MSG_LENGTH 50
#define MAX_SIGNED_MSG_LENGTH (MAX_MSG_LENGTH + CRYPTO_BYTES)
#define HASH_SIZE 32

struct Signer {
    const char* name;
    const char* message;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t signed_msg[MAX_SIGNED_MSG_LENGTH];
    size_t signed_msg_len;
};

void print_hex(const char* label, const uint8_t* data, size_t len) {
    cout << label;
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    cout << endl;
}

int main() {
    uint8_t ctx[HASH_SIZE];
    d_randombytes(ctx, HASH_SIZE);

    Signer signers[NUM_SIGNERS] = {
        {"jmzhang", "quantum secure signature"},
        {"fzh", "post-quantum SDVMS"},
        {"lei", "fast NI designated"}
    };

    // Key Generation
    auto t1 = high_resolution_clock::now();
    for (int i = 0; i < NUM_SIGNERS; i++) {
        crypto_sign_keypair(signers[i].pk, signers[i].sk);
    }
    auto t2 = high_resolution_clock::now();
    double keygen_time = duration_cast<microseconds>(t2 - t1).count() / 1000.0;
    cout << "KeyGen Time for jmzhang: " << keygen_time << " ms" << endl;

    // Signing
    size_t combined_length = 0;
    uint8_t combined_signed_msgs[MAX_SIGNED_MSG_LENGTH * NUM_SIGNERS];
    auto t3 = high_resolution_clock::now();
    for (int i = 0; i < NUM_SIGNERS; i++) {
        size_t msg_len = strlen(signers[i].message);
        crypto_sign(signers[i].signed_msg, &signers[i].signed_msg_len,
                    (const uint8_t*)signers[i].message, msg_len,
                    ctx, HASH_SIZE,
                    signers[i].sk);

        memcpy(combined_signed_msgs + combined_length,
               signers[i].signed_msg,
               signers[i].signed_msg_len);
        combined_length += signers[i].signed_msg_len;
    }
    auto t4 = high_resolution_clock::now();
    double sign_time = duration_cast<microseconds>(t4 - t3).count() / 1000.0;
    cout << "Signing + Aggregation Time: " << sign_time << " ms" << endl;

    // Simulate "hashing" the aggregated message
    uint8_t hash[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; i++) hash[i] = rand() % 256;

    // Simulate encryption (KEM)
    uint8_t kem_pk[KYBER_PUBLICKEYBYTES];
    uint8_t kem_sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t shared_alice[KYBER_SSBYTES];
    uint8_t shared_bob[KYBER_SSBYTES];

    crypto_kem_keypair(kem_pk, kem_sk);
    crypto_kem_enc(ct, shared_bob, kem_pk);
    crypto_kem_dec(shared_alice, ct, kem_sk);

    cout << "Aggregated Signature Size: " << combined_length / 1024.0 << " KB" << endl;
    system("pause");

    return 0;
}
