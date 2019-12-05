#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "ocb.h"
#include "ahead.h"

const uint8_t en[3] = "EN";
const uint8_t ck[3] = "CK";
const uint8_t de[3] = "DE";

int main(void) {
    const uint8_t* errdesc;
    uint32_t itr = 0, diff, alen, mlen;
    uint64_t _key[4], _nonce[2], _associated_data[8], _message[8],
            _out1[10], _out2[10];
    uint8_t * key = (uint8_t *) _key, * nonce = (uint8_t *) _nonce, * associated_data = (uint8_t *) _associated_data,
            * message = (uint8_t *) _message, * out1 = (uint8_t *) _out1, * out2 = (uint8_t *) _out2;
    ae_ctx ctx;
    srand(time(0));

    if (!rand()) {
        puts("RNG failed.");
        return 1;
    }
    puts("Starting...");
test:

    alen = 64;
    mlen = 64;

    for (int i = 0; i < 32; i += 8)
        key[i] = rand();

    for (int i = 0; i < 64; i += 8)
        associated_data[i] = rand();

    for (int i = 0; i < 64; i += 8)
        message[i] = rand();

    nonce[0] = rand();
    nonce[8] = rand();

    ocb_encrypt(key, nonce, 12, message, mlen, associated_data, alen, out1);
    ae_clear(&ctx);
    ae_init(&ctx, key, 32, 12);

    if (ae_encrypt(&ctx, nonce, message, mlen, associated_data, alen, out2, NULL, 1) <= 0) {
        puts("Reference error.");
        return 1;
    }

    diff = 0;
    for (int i = 0, k = mlen + 16; i < k; i++)
        diff ^= out1[i];

    for (int i = 0, k = mlen + 16; i < k; i++)
        diff ^= out2[i];

    if (diff) {
        errdesc = en;
        goto fail;
    }

    if (ocb_decrypt(key, nonce, 12,
            out1, mlen, associated_data,
            alen, out2)) {
        errdesc = ck;
        goto fail;
    }

    for (int i = 0; i < mlen; i++)
        diff ^= message[i];

    for (int i = 0; i < mlen; i++)
        diff ^= out2[i];

    if (diff) {
        errdesc = de;
        goto fail;
    }

    if (0) {
fail:
        printf("---TEST FAILED: %sCODE ERROR---\nKey:\n", errdesc);

        for (int i = 0; i < 32; i++)
            printf("%.2x, ", (uint32_t) key[i]);

        printf("\n\nIteration: %u\n", itr);
        puts("\n\nNonce:");
        for (int i = 0; i < 12; i++)
            printf("%.2x, ", (uint32_t) nonce[i]);

        puts("\n\nAssociated data:");
        for (int i = 0; i < alen; i++)
            printf("%.2x, ", (uint32_t) associated_data[i]);

        puts("\n\nMessage:");
        for (int i = 0; i < mlen; i++)
            printf("%.2x, ", (uint32_t) message[i]);

        puts("");
        return 1;
    }

    if (itr++ != 100000)
        goto test;

    puts("100k TESTS PASS!");

    return 0;
}
