/*------------------------------------------------------------------------
/ OCB Version 3 Reference Code
/-------------------------------------------------------------------------
/ Copyright (c) 2013 Ted Krovetz.
/
/ Permission to use, copy, modify, and/or distribute this software for any
/ purpose with or without fee is hereby granted, provided that the above
/ copyright notice and this permission notice appear in all copies.
/
/ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
/ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
/ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
/ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
/ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
/ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
/ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/
/ Special thanks to Keegan McAllister for suggesting several good improvements
/ Dedicated to Laurel K
/------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* Usage notes                                                             */
/* ----------------------------------------------------------------------- */

/* - When AE_PENDING is passed as the 'final' parameter of any function,
/    the length parameters must be a multiple of (BPI*16).
/  - When available, SSE or AltiVec registers are used to manipulate data.
/    So, when on machines with these facilities, all pointers passed to
/    any function should be 16-byte aligned.
/  - Plaintext and ciphertext pointers may be equal (ie, plaintext gets
/    encrypted in-place), but no other pair of pointers may be equal.
/  - This code is tested for C99 and recent versions of GCC         .      */

/* ----------------------------------------------------------------------- */
/* Includes and compiler specific definitions                              */
/* ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ahead.h"
#include "aes.h"

/* ----------------------------------------------------------------------- */
/* User configuration options                                              */
/* ----------------------------------------------------------------------- */

/* Authentication tag length */

#define OCB_TAG_LEN         16
#define BPI                  4  /* Number of blocks in buffer per ECB call */

/* L_TABLE_SZ specifies how many L values to precompute.
/  L_TABLE_SZ must be at least 3. L_TABLE_SZ*16 bytes
/  are used for L values in ae_ctx. Plaintext and ciphertexts shorter than
/  2^L_TABLE_SZ blocks need no L values calculated dynamically.            */
#define L_TABLE_SZ          16

/* ----------------------------------------------------------------------- */
/* L table lookup (or on-the-fly generation)                               */
/* ----------------------------------------------------------------------- */

#define getL(_ctx, _tz) ((_ctx)->L[_tz])

#define unequal_blocks(x, y) ((((x).l^(y).l)|((x).r^(y).r)) != 0)

/* GNU Compiler-specific intrinsics and fixes: bswap64, ntz                */

#ifdef USE_BUILTIN
#define bswap64(x) __builtin_bswap64(x)           /* Assuming GCC 4.3+ */
#define ntz(x)     __builtin_ctz((uint32_t)(x))   /* Assuming GCC 3.4+ */
#define ocb_memcpy(a,b,c) __builtin_memcpy(a,b,c)
#else
#define ocb_memcpy(a,b,c) memcpy(a,b,c)

static inline uint64_t bswap64(uint64_t _x) {
    return ((_x >> 56) | ((_x >> 40) & 0xff00) | ((_x >> 24) & 0xff0000) |
        ((_x >> 8) & 0xff000000) | ((_x << 8) & ((uint64_t) 0xff << 32)) |
        ((_x << 24) & ((uint64_t)0xff << 40)) |
        ((_x << 40) & ((uint64_t)0xff << 48)) | ((_x << 56)));
}

// count trailing zeroes in x; for each block in the message,
// ntz(blocknumber) selects an L_n value for the "offset"

int ntz(uint64_t x) {
    uint64_t y;

    if (x == 0) {
        return 64;
    }

    int n = 64;

    y = x << 32;

    if (y != 0) {
        n -= 32;
        x = y;
    }

    y = x << 16;

    if (y != 0) {
        n -= 16;
        x = y;
    }

    y = x << 8;

    if (y != 0) {
        n -= 8;
        x = y;
    }

    y = x << 4;

    if (y != 0) {
        n -= 4;
        x = y;
    }

    y = x << 2;

    if (y != 0) {
        n -= 2;
        x = y;
    }

    y = x << 1;

    if (y != 0) {
        n -= 1;
    }

    return n;
}
#endif

/* ----------------------------------------------------------------------- */
/* Define blocks and operations -- Patch if incorrect on your compiler.    */

/* ----------------------------------------------------------------------- */

static inline block xor_block(block x, block y) {
    x.l ^= y.l;
    x.r ^= y.r;
    
    return x;
}

static inline block zero_block(void) {
    const block t = {0, 0};
    
    return t;
}

static inline block swap_block(block b) {
    block r;

    r.l = bswap64(b.l);
    r.r = bswap64(b.r);

    return r;
}

/* KtopStr is reg correct by 64 bits, return mem correct */
block gen_offset(uint64_t KtopStr[3], uint32_t bot) {
    block rval;

    if (bot != 0) {
        rval.l = (KtopStr[0] << bot) | (KtopStr[1] >> (64 - bot));
        rval.r = (KtopStr[1] << bot) | (KtopStr[2] >> (64 - bot));
    } else {
        rval.l = KtopStr[0];
        rval.r = KtopStr[1];
    }

    return swap_block(rval);
}

static inline block double_block(block b) {
    uint64_t t = (uint64_t) ((int64_t) b.l >> 63);

    b.l = (b.l + b.l) ^ (b.r >> 63);
    b.r = (b.r + b.r) ^ (t & 135);

    return b;
}

static void ocb3_encrypt_blks(block *blks, uint32_t nblks, AES_KEY *key) {
    while (nblks) {
        --nblks;
        AES_Encrypt(key->rd_key, 14, (uint8_t *) (blks + nblks), (uint8_t *) (blks + nblks));
    }
}

static void ocb3_decrypt_blks(block *blks, uint32_t nblks, AES_KEY *key) {
    while (nblks) {
        --nblks;
        AES_Decrypt(key->rd_key, 14, (uint8_t *) (blks + nblks), (uint8_t *) (blks + nblks));
    }
}

/* ----------------------------------------------------------------------- */
/* Public functions                                                        */
/* ----------------------------------------------------------------------- */

/* 32-bit SSE2 and Altivec systems need to be forced to allocate memory
   on 16-byte alignments. (I believe all major 64-bit systems do already.) */

ae_ctx *ae_allocate(void) {
    return (ae_ctx *) malloc(sizeof (ae_ctx));
}

void ae_free(ae_ctx *ctx) {
    free(ctx);
}

/* ----------------------------------------------------------------------- */

void ae_clear(ae_ctx *ctx) /* Zero ae_ctx and undo initialization          */ {
    memset(ctx, 0, sizeof (ae_ctx));
}

int ae_ctx_sizeof(void) {
    return (int) sizeof (ae_ctx);
}

/* ----------------------------------------------------------------------- */

int ae_init(ae_ctx *ctx, const uint8_t *key) {
    uint32_t i;
    block tmp_blk;

    /* Initialize encryption & decryption keys */
    
    AES_KeySetupEnc((&ctx->encrypt_key)->rd_key, key);
    AES_KeySetupDec((&ctx->decrypt_key)->rd_key, key);

    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    /* Compute key-dependent values */
    AES_Encrypt((&ctx->encrypt_key)->rd_key, 14, (uint8_t *) & ctx->cached_Top, (uint8_t *) & ctx->Lstar);

    tmp_blk = swap_block(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_block(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_block(tmp_blk);
    
    for (i = 1; i < L_TABLE_SZ; i++) {
        tmp_blk = double_block(tmp_blk);
        ctx->L[i] = swap_block(tmp_blk);
    }

    return AE_SUCCESS;
}

/* ----------------------------------------------------------------------- */

static block gen_offset_from_nonce(ae_ctx *ctx, const void *nonce) {

    const union {
        uint32_t x;
        uint8_t endian;
    } little = {1};

    union {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;
    uint32_t idx;

    /* Replace cached nonce Top if needed */

    if (little.endian)
        tmp.u32[0] = 0x01000000 + ((OCB_TAG_LEN * 8 % 128) << 1);
    else
        tmp.u32[0] = 0x00000001 + ((OCB_TAG_LEN * 8 % 128) << 25);

    tmp.u32[1] = ((uint32_t *) nonce)[0];
    tmp.u32[2] = ((uint32_t *) nonce)[1];
    tmp.u32[3] = ((uint32_t *) nonce)[2];
    idx = (uint32_t) (tmp.u8[15] & 0x3f); /* Get low 6 bits of nonce  */
    tmp.u8[15] = tmp.u8[15] & 0xc0; /* Zero low 6 bits of nonce */
    
    if (unequal_blocks(tmp.bl, ctx->cached_Top)) { /* Cached?       */
        ctx->cached_Top = tmp.bl; /* Update cache, KtopStr    */

        AES_Encrypt((&ctx->encrypt_key)->rd_key, 14, tmp.u8, (uint8_t *) & ctx->KtopStr);
        
        if (little.endian) { /* Make Register Correct    */
            ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
            ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
        }
        
        ctx->KtopStr[2] = ctx->KtopStr[0] ^
                (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
    }
    
    return gen_offset(ctx->KtopStr, idx);
}

static void process_ad(ae_ctx *ctx, const void *ad, int ad_len, int final) {

    union {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;
    
    block ad_offset, ad_checksum;
    const block * adp = (block *) ad;
    uint32_t i, k, tz, remaining;

    ad_offset = ctx->ad_offset;
    ad_checksum = ctx->ad_checksum;
    i = ad_len / (BPI * 16);
    
    if (i) {
        uint32_t ad_block_num = ctx->ad_blocks_processed;
        
        do {
            block ta[BPI], oa[BPI];

            ad_block_num += BPI;
            tz = ntz(ad_block_num);

            oa[0] = xor_block(ad_offset, ctx->L[0]);
            ta[0] = xor_block(oa[0], adp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], adp[1]);
            oa[2] = xor_block(ad_offset, ctx->L[1]);
            ta[2] = xor_block(oa[2], adp[2]);

            ad_offset = xor_block(oa[2], getL(ctx, tz));
            ta[3] = xor_block(ad_offset, adp[3]);

            ocb3_encrypt_blks(ta, BPI, &ctx->encrypt_key);

            ad_checksum = xor_block(ad_checksum, ta[0]);
            ad_checksum = xor_block(ad_checksum, ta[1]);
            ad_checksum = xor_block(ad_checksum, ta[2]);
            ad_checksum = xor_block(ad_checksum, ta[3]);

            adp += BPI;
        } while (--i);

        ctx->ad_blocks_processed = ad_block_num;
        ctx->ad_offset = ad_offset;
        ctx->ad_checksum = ad_checksum;
    }

    if (final) {
        block ta[BPI];

        /* Process remaining associated data, compute its tag contribution */
        remaining = ((uint32_t) ad_len) % (BPI * 16);
        if (remaining) {
            k = 0;

            if (remaining >= 32) {
                ad_offset = xor_block(ad_offset, ctx->L[0]);
                ta[k] = xor_block(ad_offset, adp[k]);
                ad_offset = xor_block(ad_offset, getL(ctx, ntz(k + 2)));
                ta[k + 1] = xor_block(ad_offset, adp[k + 1]);
                remaining -= 32;
                k += 2;
            }

            if (remaining >= 16) {
                ad_offset = xor_block(ad_offset, ctx->L[0]);
                ta[k] = xor_block(ad_offset, adp[k]);
                remaining = remaining - 16;
                ++k;
            }

            if (remaining) {
                ad_offset = xor_block(ad_offset, ctx->Lstar);
                tmp.bl = zero_block();
                ocb_memcpy(tmp.u8, adp + k, remaining);
                tmp.u8[remaining] = (uint8_t) 0x80u;
                ta[k] = xor_block(ad_offset, tmp.bl);
                ++k;
            }

            ocb3_encrypt_blks(ta, k, &ctx->encrypt_key);

            switch (k) {
                case 4: ad_checksum = xor_block(ad_checksum, ta[3]);
                case 3: ad_checksum = xor_block(ad_checksum, ta[2]);
                case 2: ad_checksum = xor_block(ad_checksum, ta[1]);
                case 1: ad_checksum = xor_block(ad_checksum, ta[0]);
            }

            ctx->ad_checksum = ad_checksum;
        }
    }
}

/* ----------------------------------------------------------------------- */

int ae_encrypt(ae_ctx * ctx,
        const void * restrict nonce,
        const void * restrict pt,
        int pt_len,
        const void * restrict ad,
        int ad_len,
        void * restrict ct,
        void * restrict tag,
        int final) {

    union {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;

    block offset, checksum;
    uint32_t i, k;
    block * ctp = (block *) ct;
    const block * ptp = (block *) pt;

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
        ctx->ad_offset = ctx->checksum = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed = 0;

        if (ad_len >= 0)
            ctx->ad_checksum = zero_block();
    }

    /* Process associated data */
    if (ad_len > 0)
        process_ad(ctx, ad, ad_len, final);

    /* Encrypt plaintext data BPI blocks at a time */
    offset = ctx->offset;
    checksum = ctx->checksum;
    i = pt_len / (BPI * 16);

    if (i) {
        block oa[BPI];
        uint32_t block_num = ctx->blocks_processed;
        oa[BPI - 1] = offset;

        do {
            block ta[BPI];

            block_num += BPI;
            oa[0] = xor_block(oa[BPI - 1], ctx->L[0]);
            ta[0] = xor_block(oa[0], ptp[0]);
            checksum = xor_block(checksum, ptp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ptp[1]);
            checksum = xor_block(checksum, ptp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ptp[2]);
            checksum = xor_block(checksum, ptp[2]);

            oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
            ta[3] = xor_block(oa[3], ptp[3]);
            checksum = xor_block(checksum, ptp[3]);

            ocb3_encrypt_blks(ta, BPI, &ctx->encrypt_key);

            ctp[0] = xor_block(ta[0], oa[0]);
            ctp[1] = xor_block(ta[1], oa[1]);
            ctp[2] = xor_block(ta[2], oa[2]);
            ctp[3] = xor_block(ta[3], oa[3]);

            ptp += BPI;
            ctp += BPI;
        } while (--i);

        ctx->offset = offset = oa[BPI - 1];
        ctx->blocks_processed = block_num;
        ctx->checksum = checksum;
    }

    if (final) {
        block ta[BPI + 1], oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        uint32_t remaining = ((uint32_t) pt_len) % (BPI * 16);
        k = 0; /* How many blocks in ta[] need ECBing */

        if (remaining) {
            if (remaining >= 32) {
                oa[k] = xor_block(offset, ctx->L[0]);
                ta[k] = xor_block(oa[k], ptp[k]);
                checksum = xor_block(checksum, ptp[k]);
                offset = oa[k + 1] = xor_block(oa[k], ctx->L[1]);
                ta[k + 1] = xor_block(offset, ptp[k + 1]);
                checksum = xor_block(checksum, ptp[k + 1]);
                remaining -= 32;
                k += 2;
            }

            if (remaining >= 16) {
                offset = oa[k] = xor_block(offset, ctx->L[0]);
                ta[k] = xor_block(offset, ptp[k]);
                checksum = xor_block(checksum, ptp[k]);
                remaining -= 16;
                ++k;
            }

            if (remaining) {
                tmp.bl = zero_block();
                ocb_memcpy(tmp.u8, ptp + k, remaining);
                tmp.u8[remaining] = (uint8_t) 0x80u;
                checksum = xor_block(checksum, tmp.bl);
                ta[k] = offset = xor_block(offset, ctx->Lstar);
                ++k;
            }
        }

        offset = xor_block(offset, ctx->Ldollar); /* Part of tag gen */
        ta[k] = xor_block(offset, checksum); /* Part of tag gen */

        ocb3_encrypt_blks(ta, k + 1, &ctx->encrypt_key);

        offset = xor_block(ta[k], ctx->ad_checksum); /* Part of tag gen */

        if (remaining) {
            --k;
            tmp.bl = xor_block(tmp.bl, ta[k]);
            ocb_memcpy(ctp + k, tmp.u8, remaining);
        }

        switch (k) {
            case 3: ctp[2] = xor_block(ta[2], oa[2]);
            case 2: ctp[1] = xor_block(ta[1], oa[1]);
            case 1: ctp[0] = xor_block(ta[0], oa[0]);
        }

        /* Tag is placed at the correct location
         */
        if (tag) {
            *(block *) tag = offset;
        } else {
            ocb_memcpy((char *) ct + pt_len, &offset, OCB_TAG_LEN);
            pt_len += OCB_TAG_LEN;
        }
    }

    return pt_len;
}

/* ----------------------------------------------------------------------- */

/* Compare two regions of memory, taking a constant amount of time for a
   given buffer size -- under certain assumptions about the compiler
   and machine, of course.

   Use this to avoid timing side-channel attacks.

   Returns 0 for memory regions with equal contents; non-zero otherwise. */
static int constant_time_memcmp(const void *av, const void *bv, size_t n) {
    const uint8_t *a = (const uint8_t *) av;
    const uint8_t *b = (const uint8_t *) bv;
    uint8_t result = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        result |= *a ^ *b;
        a++;
        b++;
    }

    return (int) result;
}

int ae_decrypt(ae_ctx * ctx,
        const void * restrict nonce,
        const void * restrict ct,
        int ct_len,
        const void * restrict ad,
        int ad_len,
        void * restrict pt,
        const void * restrict tag,
        int final) {

    union {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;
    block offset, checksum;
    uint32_t i, k;
    block *ctp = (block *) ct;
    block *ptp = (block *) pt;

    /* Reduce ct_len tag bundled in ct */
    if ((final) && (!tag))
        ct_len -= OCB_TAG_LEN;

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
        ctx->ad_offset = ctx->checksum = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed = 0;
        if (ad_len >= 0)
            ctx->ad_checksum = zero_block();
    }

    /* Process associated data */
    if (ad_len > 0)
        process_ad(ctx, ad, ad_len, final);

    /* Encrypt plaintext data BPI blocks at a time */
    offset = ctx->offset;
    checksum = ctx->checksum;
    i = ct_len / (BPI * 16);
    if (i) {
        block oa[BPI];
        uint32_t block_num = ctx->blocks_processed;
        oa[BPI - 1] = offset;
        do {
            block ta[BPI];
            block_num += BPI;
            oa[0] = xor_block(oa[BPI - 1], ctx->L[0]);
            ta[0] = xor_block(oa[0], ctp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ctp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ctp[2]);

            oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
            ta[3] = xor_block(oa[3], ctp[3]);

            ocb3_decrypt_blks(ta, BPI, &ctx->decrypt_key);
            ptp[0] = xor_block(ta[0], oa[0]);
            checksum = xor_block(checksum, ptp[0]);
            ptp[1] = xor_block(ta[1], oa[1]);
            checksum = xor_block(checksum, ptp[1]);
            ptp[2] = xor_block(ta[2], oa[2]);
            checksum = xor_block(checksum, ptp[2]);
            ptp[3] = xor_block(ta[3], oa[3]);
            checksum = xor_block(checksum, ptp[3]);

            ptp += BPI;
            ctp += BPI;
        } while (--i);
        ctx->offset = offset = oa[BPI - 1];
        ctx->blocks_processed = block_num;
        ctx->checksum = checksum;
    }

    if (final) {
        block ta[BPI + 1], oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        uint32_t remaining = ((uint32_t) ct_len) % (BPI * 16);
        k = 0; /* How many blocks in ta[] need ECBing */
        if (remaining) {
            if (remaining >= 32) {
                oa[k] = xor_block(offset, ctx->L[0]);
                ta[k] = xor_block(oa[k], ctp[k]);
                offset = oa[k + 1] = xor_block(oa[k], ctx->L[1]);
                ta[k + 1] = xor_block(offset, ctp[k + 1]);
                remaining -= 32;
                k += 2;
            }
            if (remaining >= 16) {
                offset = oa[k] = xor_block(offset, ctx->L[0]);
                ta[k] = xor_block(offset, ctp[k]);
                remaining -= 16;
                ++k;
            }
            if (remaining) {
                block pad;
                offset = xor_block(offset, ctx->Lstar);
                
                AES_Encrypt((&ctx->encrypt_key)->rd_key, 14, (uint8_t *) & offset, tmp.u8);
                
                pad = tmp.bl;
                ocb_memcpy(tmp.u8, ctp + k, remaining);
                tmp.bl = xor_block(tmp.bl, pad);
                tmp.u8[remaining] = (uint8_t) 0x80u;
                ocb_memcpy(ptp + k, tmp.u8, remaining);
                checksum = xor_block(checksum, tmp.bl);
            }
        }
        
        ocb3_decrypt_blks(ta, k, &ctx->decrypt_key);
        
        switch (k) {
            case 3: ptp[2] = xor_block(ta[2], oa[2]);
                checksum = xor_block(checksum, ptp[2]);
            case 2: ptp[1] = xor_block(ta[1], oa[1]);
                checksum = xor_block(checksum, ptp[1]);
            case 1: ptp[0] = xor_block(ta[0], oa[0]);
                checksum = xor_block(checksum, ptp[0]);
        }

        /* Calculate expected tag */
        offset = xor_block(offset, ctx->Ldollar);
        tmp.bl = xor_block(offset, checksum);
        
        AES_Encrypt((&ctx->encrypt_key)->rd_key, 14, tmp.u8, tmp.u8);
        
        tmp.bl = xor_block(tmp.bl, ctx->ad_checksum); /* Full tag */

        /* Compare with proposed tag, change ct_len if invalid */
        if (tag) {
            if (unequal_blocks(tmp.bl, *(block *) tag))
                ct_len = AE_INVALID;
        } else {
            int len = OCB_TAG_LEN;

            if (tag) {
                if (constant_time_memcmp(tag, tmp.u8, len) != 0)
                    ct_len = AE_INVALID;
            } else {
                if (constant_time_memcmp((char *) ct + ct_len, tmp.u8, len) != 0)
                    ct_len = AE_INVALID;
            }
        }
    }

    return ct_len;
}
