#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Encrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  IV, can be a counter, don't use the
 * same nonce for a key with different message/associated data.
 * @param nonce_length           A trivial parameter about nonce
 * length in bytes. 12 is the recommended value.
 * @param message                Data to be encrypted.
 * @param message_length         Data length in bytes.
 * @param associated_data        See the README.md for this.
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with length [message_length + 16 bytes]
 */
void ocb_encrypt(const uint8_t key[32], const uint8_t nonce[15], int nonce_length,
  const uint8_t *message, int message_length, const uint8_t *associated_data,
  int associated_data_length, uint8_t *out);

/**
 * Decrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  The IV used with the encryption function
 * @param nonce_length           A trivial parameter about nonce
 * length in bytes. 12 is the recommended value.
 * @param encrypted              Encrypted data (aka ciphertext), with
 * the 16-byte authentication tag appended to it.
 * @param encrypted_length       Ciphertext length in bytes, excluding
 * the 16-byte authentication tag.
 * @param associated_data        See the README.md for this.
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with length [encrypted_length]
 * @return                       MUST BE CHECKED. Zero if decipher succesful.
 */
int ocb_decrypt(const uint8_t key[32], const uint8_t nonce[15], int nonce_length,
  const uint8_t *encrypted, int encrypted_length, const uint8_t *associated_data,
  int associated_data_length, uint8_t *out);

#ifdef __cplusplus
}
#endif
