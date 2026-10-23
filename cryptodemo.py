import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidKey, InvalidSignature


# scrypt cost parameters. n is the main work factor (memory and CPU).
# Higher n = slower = harder to brute force. These are sensible demo values.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


# ---------------------------------------------------------------------------
# Case 1: password storage with scrypt (a memory hard KDF)
# Real world: how any website should store user passwords. The password itself
# is never stored. We store a random salt plus the slow hash of the password.
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(16)  # a fresh random salt per password
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    digest = kdf.derive(password.encode())
    # store salt and digest together so we can verify later
    return f"scrypt${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, digest_b64 = stored.split("$")
        salt, digest = unb64(salt_b64), unb64(digest_b64)
    except ValueError:
        return False
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    try:
        kdf.verify(password.encode(), digest)  # constant time comparison inside
        return True
    except InvalidKey:
        return False


# ---------------------------------------------------------------------------
# Case 2: encrypted vault with AES-256-GCM (AEAD)
# Real world: a password manager, or encrypting an API key / secret note before
# saving it to disk. AES-GCM gives confidentiality AND integrity at once: if the
# ciphertext is changed by one bit, decryption fails instead of returning junk.
# The AES key is derived from a master passphrase with scrypt.
# ---------------------------------------------------------------------------

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode())


def encrypt(passphrase: str, plaintext: str) -> str:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(12)  # a one time number, never reused with the same key
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    blob = {"salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
    return json.dumps(blob)


def decrypt(passphrase: str, blob_json: str) -> str:
    blob = json.loads(blob_json)
    salt = unb64(blob["salt"])
    nonce = unb64(blob["nonce"])
    ciphertext = unb64(blob["ciphertext"])
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    # raises InvalidTag if the key is wrong OR the ciphertext was tampered with
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# ---------------------------------------------------------------------------
# Case 3: digital signatures with Ed25519 (EdDSA)
# Real world: signing a software release or a transaction so anyone can verify
# it really came from you and was not changed. Ed25519 is used instead of ECDSA
# because it uses deterministic nonces, which avoids the nonce reuse attack from
# Lecture 5 (slide 8, "the big lie of ECDSA").
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    return b64(priv_bytes), b64(pub_bytes)


def sign_message(private_b64: str, message: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(unb64(private_b64))
    signature = private_key.sign(message.encode())
    return b64(signature)


def verify_signature(public_b64: str, message: str, signature_b64: str) -> bool:
    public_key = Ed25519PublicKey.from_public_bytes(unb64(public_b64))
    try:
        public_key.verify(unb64(signature_b64), message.encode())
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# The guided demo: runs all three cases and shows tamper detection
# ---------------------------------------------------------------------------

def line(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def run_demo() -> None:
    line("CASE 1  User login: password storage with scrypt")
    stored = hash_password("CorrectHorse!42")
    print("Stored in the database (no plain password):")
    print("  " + stored)
    print("Login with the right password :", verify_password("CorrectHorse!42", stored))
    print("Login with a wrong password   :", verify_password("wrong-password", stored))
    print("Note: the same password hashed again gives a DIFFERENT value,")
    print("because each hash uses a new random salt:")
    print("  " + hash_password("CorrectHorse!42"))

    line("CASE 2  Encrypted vault: AES-256-GCM (encryption at rest)")
    secret = "my bank card: 4111 1111 1111 1111"
    blob = encrypt("master-passphrase", secret)
    print("Secret stored on disk (encrypted, unreadable):")
    print("  " + blob)
    print("Decrypt with the right passphrase :", decrypt("master-passphrase", blob))
    try:
        decrypt("wrong-passphrase", blob)
    except Exception as exc:
        print("Decrypt with a wrong passphrase   : REJECTED (" + type(exc).__name__ + ")")
    # tamper with one byte of the ciphertext and try again
    tampered = json.loads(blob)
    raw = bytearray(unb64(tampered["ciphertext"]))
    raw[0] ^= 0x01  # flip one bit
    tampered["ciphertext"] = b64(bytes(raw))
    try:
        decrypt("master-passphrase", json.dumps(tampered))
    except Exception as exc:
        print("Decrypt after tampering           : REJECTED (" + type(exc).__name__ + ")")
    print("-> AES-GCM detects any change. It never returns altered data as valid.")

    line("CASE 3  Signing a release: Ed25519 digital signature")
    priv, pub = generate_keypair()
    message = "release v1.0.0 sha256=ab12cd34"
    signature = sign_message(priv, message)
    print("Message  :", message)
    print("Signature:", signature)
    print("Verify original message  :", verify_signature(pub, message, signature))
    changed = "release v1.0.0 sha256=DEADBEEF"
    print("Verify a changed message :", verify_signature(pub, changed, signature))
    print("-> Only the holder of the private key can sign; anyone can verify with")
    print("   the public key, and any change breaks the signature.")
    print()


# ---------------------------------------------------------------------------
# Command line interface
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Proper cryptography usage demo (Lab 5).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="run the guided demo of all three cases")

    p = sub.add_parser("hash-password", help="hash a password for storage (scrypt)")
    p.add_argument("password")

    p = sub.add_parser("verify-password", help="check a password against a stored hash")
    p.add_argument("password")
    p.add_argument("stored")

    p = sub.add_parser("encrypt", help="encrypt text with a passphrase (AES-256-GCM)")
    p.add_argument("passphrase")
    p.add_argument("text")

    p = sub.add_parser("decrypt", help="decrypt a blob with a passphrase")
    p.add_argument("passphrase")
    p.add_argument("blob")

    sub.add_parser("keygen", help="generate an Ed25519 key pair")

    p = sub.add_parser("sign", help="sign a message with a private key")
    p.add_argument("private_key")
    p.add_argument("message")

    p = sub.add_parser("verify", help="verify a signature with a public key")
    p.add_argument("public_key")
    p.add_argument("message")
    p.add_argument("signature")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "hash-password":
        print(hash_password(args.password))
    elif args.command == "verify-password":
        print("OK" if verify_password(args.password, args.stored) else "FAIL")
    elif args.command == "encrypt":
        print(encrypt(args.passphrase, args.text))
    elif args.command == "decrypt":
        try:
            print(decrypt(args.passphrase, args.blob))
        except Exception as exc:
            print("REJECTED:", type(exc).__name__, file=sys.stderr)
            return 1
    elif args.command == "keygen":
        priv, pub = generate_keypair()
        print("private_key:", priv)
        print("public_key :", pub)
    elif args.command == "sign":
        print(sign_message(args.private_key, args.message))
    elif args.command == "verify":
        print("OK" if verify_signature(args.public_key, args.message, args.signature) else "FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
