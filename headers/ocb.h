#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
    
#define USE_BUILTIN


/* Authentication tag length */

#define OCB_TAG_LEN     16  /* 128 bits */
#define NONCE_MAX       15  /* 96 bits used of 120 */
#define ROUNDS          14

void hash(const uint8_t *, const uint8_t *, int, const uint8_t [][16],
        const uint8_t *, uint8_t *);

/**
 * Encrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  IV, can be a counter (15 bytes) 12 used
 * @param message                Data to be encrypted.
 * @param message_length         Data length in bytes.
 * @param associated_data
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with message_length + TAG
 */
void ocb_encrypt(const uint8_t [], const uint8_t [],
        const uint8_t *, int, const uint8_t *, int, uint8_t *);

/**
 * Decrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  The IV used with encryption (15 bytes) 12 used
 * @param encrypted              Encrypted data, with the TAG
 * @param encrypted_length       Ciphertext length in bytes, excluding TAG
 * @param associated_data
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with length [encrypted_length]
 * @return                       MUST BE CHECKED. Zero if decipher successful.
 */
int ocb_decrypt(const uint8_t [], const uint8_t [],
        const uint8_t *, int, const uint8_t *, int, uint8_t *);

#ifdef __cplusplus
}
#endif
