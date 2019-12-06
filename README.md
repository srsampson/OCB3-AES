### AES OCB
OCB mode (Offset Codebook Mode) is an authenticated encryption mode of operation for cryptographic block ciphers. OCB mode was designed by Phillip Rogaway, who credits Mihir Bellare, John Black, and Ted Krovetz with assistance and comments on the designs. It is based on the authenticated encryption mode IAPM due to Charanjit S. Jutla.

This is a pure C implementation of AES OCB3. Full name: ```AEAD_AES_256_OCB_TAGLEN128```

This code is only for 256 bit keys. It has TAGLEN of 128 bits.

OCB mode was designed to provide both message authentication and privacy. It is essentially a scheme for integrating a Message Authentication Code (MAC) into the operation of a block cipher. In this way, OCB mode avoids the need to use two systems: a MAC for authentication and encryption for privacy. This results in lower computational cost compared to using separate encryption and authentication functions. 

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
