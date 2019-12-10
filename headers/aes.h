/**
 * aes.h
 *
 * @version 3.0 (December 2000)
 *
 * C code for the AES cipher
 *
 * @author Vincent Rijmen
 * @author Antoon Bosselaers
 * @author Paulo Barreto
 *
 * This code is hereby placed in the public domain.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdint.h>

int AES_KeySetupEnc(uint32_t *, const uint8_t *);
int AES_KeySetupDec(uint32_t *, const uint8_t *);

void AES_Encrypt(const uint32_t *, int, const uint8_t *, uint8_t *);
void AES_Decrypt(const uint32_t *, int, const uint8_t *, uint8_t *);

#ifdef __cplusplus
}
#endif
