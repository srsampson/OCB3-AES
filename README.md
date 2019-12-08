### AES OCB
OCB mode (Offset Codebook Mode) is an authenticated encryption mode of operation for cryptographic block ciphers. It is based on the Integrity Aware Parallelizable Mode (IAPM).

This is a C implementation of AES OCB3. Full name: ```AEAD_AES_256_OCB_TAGLEN128```

This code is fixed for 256 bit keys. It has TAGLEN of 128 bits.

OCB mode was designed to provide both message authentication and privacy. It is essentially a scheme for integrating a Message Authentication Code (MAC) into the operation of a block cipher. In this way, OCB mode avoids the need to use two systems: a MAC for authentication and encryption for privacy. This results in lower computational cost compared to using separate encryption and authentication functions.

When an Authenticated Encryption (AE) scheme allows for the authentication at the same time that a plaintext is being encrypted, the scheme is an Authenticated Encryption with Associated Data (AEAD) scheme.

OCB3 is an AEAD scheme that depends on the AES Electronic Code Book (ECB) block cipher. 

### Performance
OCB3 performance overhead is minimal compared to classical, non-authenticating modes like CBC. The test program executes 100,000 loops. Output from a Core I5 CPU was:
```
Starting...
100k TESTS PASS!

real	0m10.408s
user	0m10.407s
sys	0m0.000s
```
Which looks like about 104 micro-seconds per loop in user time.

### Nonce Requirements
The nonce is fixed size at 96 bits (12 bytes). It is crucial during encryption, that you don't repeat a nonce. Nonces do not need to be secret, and a counter may be used. If two parties send OCB-encrypted plaintexts to one another using the same key, then the nonces used by the two parties must be partitioned so that no nonce used by one party could be used by the other.

### Encryption: OCB-ENCRYPT
This function computes a ciphertext (which includes a bundled authentication tag) when given a plaintext, associated data, nonce, and key. For each invocation of OCB-ENCRYPT using the same key, the value of the nonce must be distinct.

### Decryption: OCB-DECRYPT
This function computes a plaintext when given a ciphertext, associated data, nonce, and key. An authentication tag is embedded in the ciphertext. If the tag is not correct for the ciphertext, associated data, nonce, and key, then an INVALID signal is produced.
   
### Processing Associated Data: HASH
OCB has the ability to authenticate unencrypted associated data at the same time that it provides for authentication and encrypts a plaintext. The hash function is central to providing this functionality. If an application has no associated data, then the associated data should be considered to be the empty string. The hash function always returns zeros (128) when the associated data is the empty string.
