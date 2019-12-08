#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "ocb.h"
#include "ahead.h"

const char en[3] = "EN";
const char ck[3] = "CK";
const char de[3] = "DE";

int main(void) {
    const char *errdesc;
    int itr = 0;
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t associated_data[64];
    uint8_t message[64];
    uint8_t out1[80];
    uint8_t out2[80];
    ae_ctx ctx;
    
    srand(time(0));

    if (!rand()) {
        puts("RNG failed.");
        return 1;
    }
    puts("Starting...");
test:

    for (int i = 0; i < 12; i++)
        nonce[i] = rand();
    
    for (int i = 0; i < 32; i++)
        key[i] = rand();

    for (int i = 0; i < 64; i++)
        associated_data[i] = rand();

    for (int i = 0; i < 64; i++)
        message[i] = rand();

    ocb_encrypt(key, nonce, message, 64, associated_data, 64, out1);
    ae_clear(&ctx);
    ae_init(&ctx, key);

    if (ae_encrypt(&ctx, nonce, message, 64, associated_data, 64, out2, NULL, 1) <= 0) {
        puts("Reference error.");
        return 1;
    }

    uint8_t diff = 0;
    
    for (int i = 0, k = 64 + 16; i < k; i++)
        diff ^= out1[i];

    for (int i = 0, k = 64 + 16; i < k; i++)
        diff ^= out2[i];

    if (diff != 0) {
        errdesc = en;
        goto fail;
    }

    if (ocb_decrypt(key, nonce, out1, 64, associated_data, 64, out2)) {
        errdesc = ck;
        goto fail;
    }

    for (int i = 0; i < 64; i++)
        diff ^= message[i];

    for (int i = 0; i < 64; i++)
        diff ^= out2[i];

    if (diff != 0) {
        errdesc = de;
        goto fail;
    }

    if (0) {
fail:
        printf("---TEST FAILED: %sCODE ERROR---\nKey:\n", errdesc);

        for (int i = 0; i < 32; i++)
            printf("%.2x, ", (uint32_t) key[i]);

        printf("\n\nIteration: %d\n", itr);
        puts("\n\nNonce:");
        for (int i = 0; i < 12; i++)
            printf("%.2x, ", (uint32_t) nonce[i]);

        puts("\n\nAssociated data:");
        for (int i = 0; i < 64; i++)
            printf("%.2x, ", (uint32_t) associated_data[i]);

        puts("\n\nMessage:");
        for (int i = 0; i < 64; i++)
            printf("%.2x, ", (uint32_t) message[i]);

        puts("");
        return 1;
    }

    if (itr++ != 100000)
        goto test;

    puts("100k TESTS PASS!");

    return 0;
}
