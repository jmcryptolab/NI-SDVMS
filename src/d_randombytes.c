#include "d_randombytes.h"
#include <stdlib.h>
void d_randombytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
}
