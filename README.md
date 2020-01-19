### OCB3 AES
OCB mode (Offset Codebook Mode) is an authenticated encryption mode of operation for cryptographic block ciphers. Authenticated encryption provides both confidentiality and authenticity within a single scheme.

This is a C implementation of AES OCB3. Full name: ```AEAD_AES_256_OCB_TAGLEN128```

This C code is fixed for 256 bit keys, and TAGLEN of 128 bits. The nonce must be 96 bits.

OCB3 mode provide both message authentication and privacy. It is essentially a scheme for integrating a Message Authentication Code (MAC) into the operation of a block cipher. Thus, it avoids the need for two separate systems: a MAC for authentication and encryption for privacy. Which improves execution speed.

When an Authenticated Encryption (AE) scheme allows for Associated Data (AD) at the same time that a plaintext is being encrypted and authenticated, the scheme is an Authenticated Encryption with Associated Data (AEAD) scheme. OCB3 is an AEAD scheme that depends on the AES Electronic Code Book (ECB) block cipher. For example, network packet headers need integrity, and must be visible, while the payload must have both integrity and confidentiality. Both need authenticity.

### Performance
OCB3 performance overhead is minimal compared to classical, non-authenticating modes like CBC. The test program was run with 100,000 loops. It was compiled with the ```-O3``` option which makes it run about 10 times faster. Output from a Core I3 CPU was:
```
Starting...
100k TESTS PASS!

real	0m1.217s
user	0m1.209s
sys	0m0.008s
```
Which looks like about 12 micro-seconds per loop in user time.

I've changed the test program somewhat, to output more data and see how it works.

### Nonce Requirements
The nonce is fixed size at 96 bits (12 bytes). It is crucial during encryption, that you don't repeat a nonce. Nonces do not need to be secret, and a counter may be used. If two parties send OCB-encrypted plaintexts to one another using the same key, then the nonces used by the two parties must be partitioned so that no nonce used by one party could be used by the other.

### Encryption: OCB-ENCRYPT
This function computes a ciphertext and a bundled authentication TAG, when given a plaintext, nonce, and key. For each invocation of OCB-ENCRYPT using the same key, the value of the nonce must be distinct. You can also include optional Associated Data, and its Hash will be added to the authentication TAG.

### Decryption: OCB-DECRYPT
This function computes a plaintext when given a ciphertext, nonce, and key. You can also include an optional Associated Data, or a Null. The authentication TAG is embedded in the ciphertext. If the TAG is not correct for the ciphertext, associated data, nonce, and key, then an INVALID signal is produced.
   
### Processing Associated Data: HASH
OCB has the ability to authenticate unencrypted associated data at the same time that it provides for authentication and encrypts a plaintext. The hash function is central to providing this functionality. If an application has no associated data, then the associated data should be considered to be the empty string. The hash function always returns zeros (128) when the associated data is the empty string. The hash function is not accessable externally, and its output is used by the encrypt and decrypt functions based on the unencrypted associated data.
