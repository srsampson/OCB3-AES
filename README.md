### AES OCB

This is a pure C implementation of AES OCB3, originally by https://github.com/DesWurstes.
Full name: AEAD_AES_256_OCB_TAGLEN128

This code is only for 256 bit keys. It has TAGLEN of 128 bits. Allows encryption and authentication in a single pass. Factor of 2-6 times faster compared to other AES modes.

Timing-attack proof. Everything is constant time, as long as the data length, nonce length, and associated data length is constant.

### What is Associated Data?

You can send receiver a message in the plaintext, hash and sign it. You add "associated data" as that
plaintext while encrypting. The receiver will know in advance this associated data, in order to decode the ciphertext.
This way the receiver can verify the associated data is not tampered with. The "associated data" does not make the ciphertext longer.
