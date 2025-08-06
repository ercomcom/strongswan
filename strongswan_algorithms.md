# Strongswan Supported Algorithms

This document lists the cryptographic algorithms supported by Strongswan for IKE and IPsec, as found in the source code.

## IKE (Internet Key Exchange) Algorithms

IKE uses a variety of cryptographic algorithms for key exchange and authentication. The following tables list the supported algorithms for IKE.

### Encryption Algorithms (ENCR)

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| DES | `des` | `src/libstrongswan/plugins/des/des_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| 3DES | `3des` | `src/libstrongswan/plugins/des/des_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| AES-CBC | `aes`, `aes128`, `aes192`, `aes256` | `src/libstrongswan/plugins/aes/aes_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c`, `src/libstrongswan/plugins/padlock/padlock_plugin.c` |
| AES-CTR | `aes128ctr`, `aes192ctr`, `aes256ctr` | `src/libstrongswan/plugins/ctr/ctr_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Camellia-CBC | `camellia`, `camellia128`, `camellia192`, `camellia256` | `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Blowfish | `blowfish`, `blowfish128`, `blowfish192`, `blowfish256` | `src/libstrongswan/plugins/blowfish/blowfish_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Serpent | `serpent`, `serpent128`, `serpent192`, `serpent256` | `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Twofish | `twofish`, `twofish128`, `twofish192`, `twofish256` | `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| NULL Encryption | `null` | `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c` |

### Integrity Algorithms (AUTH/INTEG)

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| HMAC-SHA1-96 | `sha1`, `sha` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-SHA1-160 | `sha1_160` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-SHA2-256-128 | `sha256`, `sha2_256` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-SHA2-256-96 | `sha256_96`, `sha2_256_96` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-SHA2-384-192 | `sha384`, `sha2_384` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-SHA2-512-256 | `sha512`, `sha2_512` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| HMAC-MD5-96 | `md5` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| AES-XCBC-96 | `aesxcbc` | `src/libstrongswan/plugins/xcbc/xcbc_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| AES-CMAC-96 | `aescmac` | `src/libstrongswan/plugins/cmac/cmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| Camellia-XCBC-96 | `camelliaxcbc` | `src/libstrongswan/plugins/xcbc/xcbc_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |

### Pseudo-Random Functions (PRF)

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| PRF-HMAC-SHA1 | `prfsha1` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| PRF-HMAC-SHA2-256 | `prfsha256` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| PRF-HMAC-SHA2-384 | `prfsha384` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| PRF-HMAC-SHA2-512 | `prfsha512` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| PRF-HMAC-MD5 | `prfmd5` | `src/libstrongswan/plugins/hmac/hmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| PRF-AES-XCBC | `prfaesxcbc` | `src/libstrongswan/plugins/xcbc/xcbc_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| PRF-AES-CMAC | `prfaescmac` | `src/libstrongswan/plugins/cmac/cmac_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| PRF-Camellia-XCBC | `prfcamelliaxcbc` | `src/libstrongswan/plugins/xcbc/xcbc_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |

### Key Exchange (Diffie-Hellman Groups)

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| MODP 768 | `modp768` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 1024 | `modp1024` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 1536 | `modp1536` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 2048 | `modp2048` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 3072 | `modp3072` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 4096 | `modp4096` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 6144 | `modp6144` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| MODP 8192 | `modp8192` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ECP 192 | `ecp192` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ECP 224 | `ecp224` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ECP 256 | `ecp256` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ECP 384 | `ecp384` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ECP 521 | `ecp521` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Brainpool 224 | `ecp224bp` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Brainpool 256 | `ecp256bp` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Brainpool 384 | `ecp384bp` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Brainpool 512 | `ecp512bp` | `src/libstrongswan/plugins/gmp/gmp_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/gcrypt/gcrypt_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Curve 25519 | `curve25519`, `x25519` | `src/libstrongswan/plugins/curve25519/curve25519_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Curve 448 | `curve448`, `x448` | `src/libstrongswan/plugins/curve25519/curve25519_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| ML-KEM-512 | `mlkem512` | `src/libstrongswan/plugins/ml/ml_plugin.c` |
| ML-KEM-768 | `mlkem768` | `src/libstrongswan/plugins/ml/ml_plugin.c` |
| ML-KEM-1024 | `mlkem1024` | `src/libstrongswan/plugins/ml/ml_plugin.c` |

## IPsec (Encapsulating Security Payload) Algorithms

IPsec uses a set of algorithms for encrypting and authenticating the payload data.

### AEAD (Authenticated Encryption with Associated Data) Algorithms

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| AES-CCM-8 | `aes128ccm8`, `aes192ccm8`, `aes256ccm8` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| AES-CCM-12 | `aes128ccm12`, `aes192ccm12`, `aes256ccm12` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| AES-CCM-16 | `aes128ccm16`, `aes192ccm16`, `aes256ccm16`, `aes128ccm`, `aes192ccm`, `aes256ccm` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| AES-GCM-8 | `aes128gcm8`, `aes192gcm8`, `aes256gcm8` | `src/libstrongswan/plugins/gcm/gcm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| AES-GCM-12 | `aes128gcm12`, `aes192gcm12`, `aes256gcm12` | `src/libstrongswan/plugins/gcm/gcm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| AES-GCM-16 | `aes128gcm16`, `aes192gcm16`, `aes256gcm16`, `aes128gcm`, `aes192gcm`, `aes256gcm` | `src/libstrongswan/plugins/gcm/gcm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| AES-GMAC | `aes128gmac`, `aes192gmac`, `aes256gmac` | `src/libstrongswan/plugins/gcm/gcm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c`, `src/libstrongswan/plugins/aesni/aesni_plugin.c` |
| ChaCha20-Poly1305 | `chacha20poly1305`, `chacha20poly1305compat` | `src/libstrongswan/plugins/chapoly/chapoly_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/wolfssl/wolfssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Camellia-CCM-8 | `camellia128ccm8`, `camellia192ccm8`, `camellia256ccm8` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Camellia-CCM-12 | `camellia128ccm12`, `camellia192ccm12`, `camellia256ccm12` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |
| Camellia-CCM-16 | `camellia128ccm16`, `camellia192ccm16`, `camellia256ccm16` | `src/libstrongswan/plugins/ccm/ccm_plugin.c`, `src/libstrongswan/plugins/openssl/openssl_plugin.c`, `src/libstrongswan/plugins/botan/botan_plugin.c` |

### ESN (Extended Sequence Numbers)

| Algorithm Name | Configuration Keyword | Implementation Location(s) |
| --- | --- | --- |
| No ESN | `noesn` | (built-in) |
| ESN | `esn` | (built-in) |
