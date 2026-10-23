# Lab 5 - Cryptography in practice

Software Security and Secure Development (SSSD). Author: Amirzhan Malika.

This lab shows proper cryptography usage in two parts:

1. A small command line app (`cryptodemo.py`) with three real world cases, each
   using the right cryptographic tool for the job.
2. A test of a real open-source tool, `restic`, whose main feature is
   cryptography (encrypted backups).

Everything below ties back to Lecture 5: the point is that an algorithm is
only safe when it is applied correctly.

---

## Part 1 - the app: `cryptodemo.py`

Run the guided demo (it runs all three cases and also tries to tamper with the
data to show the protection works):

```
pip install -r requirements.txt
python3 cryptodemo.py demo
```

The full output is saved in `demo_output.txt`.

### Case 1 - User login: password storage

Real world: how a website should store user passwords.

- Tool: **scrypt**, a memory-hard key derivation function (one of the three
  recommended in Lecture 5: Argon2id, bcrypt, scrypt).
- The plain password is never stored. We store a random **salt** plus the slow
  hash of the password.
- Why scrypt and not SHA-256: SHA-256 is fast, so a stolen database can be
  brute-forced billions of times per second. scrypt is slow and memory heavy on
  purpose, which makes brute force expensive.
- Why the salt: the same password produces a different stored value every time,
  so identical passwords do not look identical and precomputed tables do not work.

```
python3 cryptodemo.py hash-password "Secret123"
python3 cryptodemo.py verify-password "Secret123" "<stored-hash>"
```

### Case 2 - Encrypted vault: data at rest

Real world: a password manager, or encrypting a secret (an API key, a card
number) before saving it to disk.

- Tool: **AES-256-GCM**, which is authenticated encryption (AEAD).
- It gives confidentiality and integrity at the same time: the data is
  unreadable to anyone without the key, and if even one bit of the ciphertext is
  changed, decryption is rejected instead of returning altered data.
- The AES key is derived from a master passphrase with scrypt, and a fresh
  random **nonce** (one-time number) is used for every encryption.

```
python3 cryptodemo.py encrypt "master-passphrase" "my secret note"
python3 cryptodemo.py decrypt "master-passphrase" "<blob>"
```

In the demo, decrypting with a wrong passphrase, or after flipping one bit of
the ciphertext, is REJECTED (`InvalidTag`).

### Case 3 - Signing a release: digital signature

Real world: signing a software release or a transaction so anyone can verify it
really came from you and was not changed.

- Tool: **Ed25519** (EdDSA).
- Only the holder of the private key can sign; anyone can verify with the public
  key; any change to the message breaks the signature.
- Why Ed25519 and not ECDSA: Ed25519 uses deterministic nonces, which avoids the
  nonce-reuse attack shown in Lecture 5 (slide 8, "the big lie of ECDSA", where
  reusing a nonce lets an attacker recover the private key).

```
python3 cryptodemo.py keygen
python3 cryptodemo.py sign "<private-key>" "release v1.0.0"
python3 cryptodemo.py verify "<public-key>" "release v1.0.0" "<signature>"
```

---

## Part 2 - testing an open-source tool: `restic`

`restic` is an open-source backup program whose main feature is cryptography.
Its cryptographic model (from Lecture 5, slide 19): **AES-256 for encryption,
Poly1305 for the MAC, and a content-addressable format where every chunk is
named by its SHA-256 hash**, which makes tampering detectable.

The full test output is in `restic_test.txt`. What it shows, step by step:

1. **Initialize** an encrypted repository (protected by a password).
2. **Back up** a folder.
3. **List** the snapshot.
4. **Encryption:** a raw pack file on disk is unreadable ciphertext, not the
   original text.
5. **Integrity check** (`restic check --read-data`): restic re-reads every chunk
   and verifies it against its SHA-256 name. Result: `no errors were found`.
6. **Restore** the snapshot and confirm the restored data is identical to the
   original.
7. **Tamper detection:** we flip a single bit inside a pack file in the
   repository and run the check again. restic reports
   `ciphertext verification failed` and `repository contains errors`. This is
   exactly the property from the lecture: because chunks are addressed and
   authenticated by SHA-256 + MAC, any change is detected.

How to reproduce:

```
export RESTIC_REPOSITORY=./repo
export RESTIC_PASSWORD=lab5-strong-pass
restic init
restic backup data
restic snapshots
restic check --read-data
restic restore <snapshot-id> --target restored
```

---

## What this lab demonstrates

| Need | Wrong-but-common choice | Correct tool used here |
|---|---|---|
| Store passwords | plain text or fast SHA-256 | scrypt (memory-hard KDF) |
| Store secret data | plain file, or encryption with no integrity | AES-256-GCM (AEAD) |
| Prove who sent it | a plain hash (anyone can recompute) | Ed25519 signature |
| Trustworthy backup | just copy the files | restic: AES-256 + Poly1305 + SHA-256 addressing |

The common thread: the algorithms (AES, SHA-256) are all strong, but security
comes from applying them correctly - salts, nonces, authenticated encryption,
signatures, and integrity checks.
