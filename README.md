# HMAC - SHA 256

## HMAC

> In cryptography, a keyed-hash message authentication code (HMAC) is a specific construction for calculating a message authentication code (MAC) involving a cryptographic hash function in combination with a secret cryptographic key. As with any MAC, it may be used to simultaneously verify both the data integrity and the authentication of a message. Any cryptographic hash function, such as MD5 or SHA-1, may be used in the calculation of an HMAC; the resulting MAC algorithm is termed HMAC-MD5 or HMAC-SHA1 accordingly. The cryptographic strength of the HMAC depends upon the cryptographic strength of the underlying hash function, the size of its hash output, and on the size and quality of the key.

from [Wikipedia](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)

## SHA 256

> SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the NSA.[3] SHA stands for Secure Hash Algorithm. Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the output from execution of the algorithm) to a known and expected hash value, a person can determine the data's integrity

from [Wikipedia](https://en.wikipedia.org/wiki/SHA-2)

## Implementation

[HMAC.java](src/com/gautamk/hmac/HMAC.java)

[SHA256.java](src/com/gautamk/hmac/SHA256.java)