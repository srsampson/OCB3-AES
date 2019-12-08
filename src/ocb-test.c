#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "ocb.h"
#include "ahead.h"

#define NONCE_MAX   15
#define MSG_MAX     64
#define AD_MAX      64
#define KEY_MAX     32
#define TAG_LEN     16

const char en[3] = "EN";
const char ck[3] = "CK";
const char de[3] = "DE";

int main(void) {
    const char *errdesc;
    int itr = 0;
    uint8_t key[KEY_MAX] = {0};
    uint8_t nonce[NONCE_MAX] = {0};              // Max 120 bits
    uint8_t associated_data[AD_MAX] = {0};
    uint8_t message[MSG_MAX] = {0};
    uint8_t out1[MSG_MAX + TAG_LEN] = {0};
    uint8_t out2[MSG_MAX + TAG_LEN] = {0};
    ae_ctx ctx;
    
    srand(time(0));

    if (!rand()) {
        puts("RNG failed.");
        return 1;
    }
    puts("Starting...");
test:

    for (int i = 0; i < (NONCE_MAX - 3); i++)
        nonce[i] = rand();
    
    for (int i = 0; i < KEY_MAX; i++)
        key[i] = rand();

    for (int i = 0; i < AD_MAX; i++)
        associated_data[i] = rand();

    for (int i = 0; i < MSG_MAX; i++)
        message[i] = rand();

    ocb_encrypt(key, nonce, message, MSG_MAX, associated_data, AD_MAX, out1);
    ae_clear(&ctx);
    ae_init(&ctx, key);

    if (ae_encrypt(&ctx, nonce, message, MSG_MAX, associated_data, AD_MAX, out2, NULL, 1) <= 0) {
        puts("Reference error.");
        return 1;
    }

    uint8_t diff = 0;
    
    for (int i = 0, k = (MSG_MAX + TAG_LEN); i < k; i++)
        diff ^= out1[i];

    for (int i = 0, k = (MSG_MAX + TAG_LEN); i < k; i++)
        diff ^= out2[i];

    if (diff != 0) {
        errdesc = en;
        goto fail;
    }

    if (ocb_decrypt(key, nonce, out1, MSG_MAX, associated_data, AD_MAX, out2)) {
        errdesc = ck;
        goto fail;
    }

    for (int i = 0; i < MSG_MAX; i++)
        diff ^= message[i];

    for (int i = 0; i < MSG_MAX; i++)
        diff ^= out2[i];

    if (diff != 0) {
        errdesc = de;
        goto fail;
    }

    if (0) {
fail:
        printf("---TEST FAILED: %sCODE ERROR---\nKey:\n", errdesc);

        for (int i = 0; i < KEY_MAX; i++)
            printf("%.2x, ", (uint32_t) key[i]);

        printf("\n\nIteration: %d\n", itr);
        puts("\n\nNonce:");
        for (int i = 0; i < (NONCE_MAX - 3); i++)
            printf("%.2x, ", (uint32_t) nonce[i]);

        puts("\n\nAssociated data:");
        for (int i = 0; i < AD_MAX; i++)
            printf("%.2x, ", (uint32_t) associated_data[i]);

        puts("\n\nMessage:");
        for (int i = 0; i < MSG_MAX; i++)
            printf("%.2x, ", (uint32_t) message[i]);

        puts("");
        return 1;
    }

    if (itr++ != 100000)
        goto test;

    puts("100k TESTS PASS!");

    return 0;
}
