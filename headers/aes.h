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

#include <stdint.h>

#define MAXKC (256/32)
#define MAXKB (256/8)
#define MAXNR 14

int KeySetupEnc(uint32_t rk[], const uint8_t cipherKey[], int keyBits);
int KeySetupDec(uint32_t rk[], const uint8_t cipherKey[], int keyBits);
void Encrypt(const uint32_t rk[], int Nr, const uint8_t pt[16], uint8_t ct[16]);
void Decrypt(const uint32_t rk[], int Nr, const uint8_t ct[16], uint8_t pt[16]);
