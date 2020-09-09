# cAEAD - Committing AEAD

Committing AEAD with ChaCha20 and BLAKE3.

> **Warning:** This is an experiment created by Soatok for fun. **Don't use it.**
>
> ![Soatok disapproves of using this](https://soatok.files.wordpress.com/2020/09//soatoktelegrams2020-09.png)

#### Make sure you [read the blog post that accompanies this repository](https://soatok.blog/2020/09/09/designing-new-cryptography-for-non-standard-threat-models/).

## What does this do?

This implements an [RKR-secure](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/)
alternative to XChaCha20-Poly1305, for use in protocols that require RKR security (i.e. OPAQUE).
The primitives used (ChaCha20, BLAKE3) are secure and constant-time in software.

Although large nonces (32 bytes) are employed by this construction, it is not strictly speaking nonce misuse resistant.
If you reuse a `(nonce, key)` tuple with two different messages, attackers will learn the XOR of the two plaintexts.

(We're using the IETF variant of ChaCha20 with 96-bit nonces and 32-bit counters.)

## How to Test this Code

```
git clone https://github.com/soatok/experimental-caead
cd js
npm install
npm test
```

## Algorithm Definition

## Notation

| Symbol | Meaning |
|--------|---------|
| `:=` | Assignment (store right-side value in left-side variable) |
| <code>&#124;&#124;</code> | Concatenation |
| `var[x:y]` | Slice `var` from index `x` to `y` | 

### Constants

Algorithm prefix: `CRYPTO_CAEAD_CHACHA20BLAKE3_`

```
DOMAIN_ENCRYPT := "Soatok01"
DOMAIN_AUTH    := "Soatok}~"
NONCE_BYTES    := 32
KEY_BYTES      := 32
TAG_BYTES      := 32
```

### Encryption Algorithm

1. Split the key into an encryption key and an authentication key.
   
   ```
   encKey := BLAKE3.keyedHash(key, DOMAIN_ENCRYPT || nonce[0:19])
   authKey := BLAKE3.keyedHash(key, DOMAIN_AUTH || nonce[0:19])
   ```
2. Encrypt the message:
   
   ```
   C := ChaCha20.encrypt(plaintext, nonce[20:31], encKey, block_counter = 0)
   ```
3. Calculate the authentication tag:
   
   ```
   T := BLAKE3.keyedHash(authKey, aad || STORE64LE(aad.length) || C)
   ```
4. Return `T || C`

### Decryption Algorithm

1. Split the key into an encryption key and an authentication key.
   
   ```
   encKey := BLAKE3.keyedHash(key, DOMAIN_ENCRYPT || nonce[0:19])
   authKey := BLAKE3.keyedHash(key, DOMAIN_AUTH || nonce[0:19])
   ```
2. Realculate the authentication tag:
   
   ```
   T' := BLAKE3.keyedHash(authKey, aad || STORE64LE(aad.length) || C)
   ```
3. Compare T with T' in constant-time. If it fails, abort.
4. Decrypt the message:
   
   ```
   P := ChaCha20.decrypt(C, nonce[20:31], encKey, block_counter = 0)
   ```
5. Return the decrypted plaintext.
