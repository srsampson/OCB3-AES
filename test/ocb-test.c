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
    int itr = 1;
    int fail = 0;

test:
#ifndef PRINT
    while (itr < 100000) {
        itr++;
#endif

    for (int i = 0; i < (NONCE_MAX - 3); i++)
        nonce[i] = rand();
    
    for (int i = 0; i < KEY_MAX; i++)
        key[i] = rand();

    for (int i = 0; i < MSG_MAX; i++)
        message[i] = rand();

    if (itr == 2) {
        ocb_encrypt(key, nonce, message, MSG_MAX, NULL, 0, out1);
    } else {
        for (int i = 0; i < AD_MAX; i++)
            associated_data[i] = rand();

        ocb_encrypt(key, nonce, message, MSG_MAX, associated_data, AD_MAX, out1);
    }

    ae_clear(&ctx);
    ae_init(&ctx, key);

#ifdef PRINT
    printf("\nIteration: %d\n\n", itr);
#endif

    /* tag len set to NULL for final */

    if (itr == 2) {
        if (ae_encrypt(&ctx, nonce, message, MSG_MAX, NULL, 0, out2, NULL, 1) <= 0) {
            puts("Reference error.");
            return 1;
        }
    } else {
        if (ae_encrypt(&ctx, nonce, message, MSG_MAX, associated_data, AD_MAX, out2, NULL, 1) <= 0) {
            puts("Reference error.");
            return 1;
        }
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

    if (itr == 2) {
        if (ocb_decrypt(key, nonce, out1, MSG_MAX, NULL, 0, out2)) {
            errdesc = ck;
            goto fail;
        }
    } else {
        if (ocb_decrypt(key, nonce, out1, MSG_MAX, associated_data, AD_MAX, out2)) {
            errdesc = ck;
            goto fail;
        }
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
        printf("---TEST FAILED: %sCODE ERROR---\n", errdesc);
        fail++;
    }

#ifdef PRINT
    printf("Key:\n");

    for (int i = 0; i < KEY_MAX; i++)
        printf("%02X ", (uint32_t) key[i]);

    puts("\n\nNonce:");
    for (int i = 0; i < (NONCE_MAX - 3); i++)
        printf("%02X ", (uint32_t) nonce[i]);

    puts("\n\nAssociated data:");
    if (itr == 2) {
            printf("NULL");
    } else {
        for (int i = 0; i < AD_MAX; i++)
            printf("%02X ", (uint32_t) associated_data[i]);
    }

    puts("\n\nMessage:");
    for (int i = 0; i < MSG_MAX; i++)
        printf("%02X ", (uint32_t) message[i]);

    puts("\n\nEncrypted Message:");
    for (int i = 0; i < (MSG_MAX + TAG_LEN); i++)
        printf("%02X ", (uint32_t) out1[i]);

    puts("\n\nDecrypted Message:");
    for (int i = 0; i < MSG_MAX; i++)
        printf("%02X ", (uint32_t) out2[i]);

    puts("\n\nTAG:");
    for (int i = MSG_MAX; i < (MSG_MAX + TAG_LEN); i++)
        printf("%02X ", (uint32_t) out2[i]);

    puts("\n");

    if (itr++ != 2)
        goto test;
#else
    }
#endif

    printf("\n%d TESTS RUN, %d TESTS FAIL!\n\n", (itr - 1), fail);

    return 0;
}
