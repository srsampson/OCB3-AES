### AES OCB
OCB mode (Offset Codebook Mode) is an authenticated encryption mode of operation for cryptographic block ciphers. OCB mode was designed by Phillip Rogaway, who credits Mihir Bellare, John Black, and Ted Krovetz with assistance and comments on the designs. It is based on the authenticated encryption mode IAPM due to Charanjit S. Jutla.

This is a pure C implementation of AES OCB3. Full name: ```AEAD_AES_256_OCB_TAGLEN128```

This code is only for 256 bit keys. It has TAGLEN of 128 bits.

OCB mode was designed to provide both message authentication and privacy. It is essentially a scheme for integrating a Message Authentication Code (MAC) into the operation of a block cipher. In this way, OCB mode avoids the need to use two systems: a MAC for authentication and encryption for privacy. This results in lower computational cost compared to using separate encryption and authentication functions.

When an AE scheme allows for the authentication of unencrypted data at the same time that a plaintext is being encrypted and authenticated, the scheme is an authenticated encryption with associated data (AEAD) scheme.  Associated data can be useful when, for example, a network packet has unencrypted routing information and an encrypted payload.

OCB is an AEAD scheme that depends on the AES Electronic Code Book (ECB) blockcipher. 

### Performance
OCB performance overhead is minimal compared to classical, non-authenticating modes like CBC. OCB requires one block cipher operation per block of encrypted and authenticated message, and one block cipher operation per block of associated data. There is also one extra block cipher operation required at the end of process.

For comparison, CCM mode offering similar functionality requires twice as many block cipher operations per message block (associated data requires one, as in OCB).

The test program executes 100,000 loops. My output from a Core I5 CPU was:
```
Starting...
100k TESTS PASS!

real	0m10.408s
user	0m10.407s
sys	0m0.000s
```
Which looks like about 104 micro-seconds per loop in user time.

### Nonce Requirements
It is crucial that, as one encrypts, one does not repeat a nonce. Nonces need not be secret, and a counter may be used for them. If two parties send OCB-encrypted plaintexts to one another using the same key, then the space of nonces used by the two parties must be partitioned so that no nonce that could be used by one party to encrypt could be used by the other to encrypt (e.g., odd and even counters). Using a random number to start the count, is much more secure than always starting at the same count (0 for example).

### Encryption: OCB-ENCRYPT
This function computes a ciphertext (which includes a bundled authentication tag) when given a plaintext, associated data, nonce, and key. For each invocation of OCB-ENCRYPT using the same key K, the value of the nonce input N must be distinct.

### Decryption: OCB-DECRYPT
This function computes a plaintext when given a ciphertext, associated data, nonce, and key.  An authentication tag is embedded in the ciphertext. If the tag is not correct for the ciphertext, associated data, nonce, and key, then an INVALID signal is produced.
   
### Processing Associated Data: HASH
OCB has the ability to authenticate unencrypted associated data at the same time that it provides for authentication and encrypts a plaintext. The following hash function is central to providing this functionality. If an application has no associated data, then the associated data should be considered to exist and to be the empty string. HASH, conveniently, always returns zeros(128) when the associated data is the empty string.
