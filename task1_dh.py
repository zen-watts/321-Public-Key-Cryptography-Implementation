"""Task 1: Diffie–Hellman key exchange + AES-CBC messaging.

This script implements a full DH exchange, derives an AES-128 key from the
shared secret using SHA-256, and encrypts/decrypts two messages between Alice
and Bob. It demonstrates both a toy DH group and a real 1024-bit IETF group.
"""

import hashlib
import secrets

try:
    # PyCryptodome provides AES and PKCS#7 padding utilities.
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as exc:  # pragma: no cover - helpful error for students
    raise SystemExit(
        "PyCryptodome is required. Install with: pip install pycryptodome"
    ) from exc

# IETF 1024-bit MODP group (RFC 3526, Group 2).
# We use the assignment's notation: q is the prime modulus, alpha (g) is the generator.
IETF_1024_Q = int(
    """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""),
    16,
)
IETF_1024_G = 2

# Toy parameters required by the assignment.
TOY_Q = 37
TOY_G = 5


def int_to_bytes(value: int) -> bytes:
    """Convert an integer to big-endian bytes (with a 0-byte for value=0)."""
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def derive_aes_key(shared_secret: int) -> bytes:
    """Derive a 128-bit AES key from the DH shared secret using SHA-256."""
    digest = hashlib.sha256(int_to_bytes(shared_secret)).digest()
    return digest[:16]


def dh_keypair(q: int, g: int) -> tuple[int, int]:
    """Generate a DH private/public keypair (x, y=g^x mod q)."""
    # Use a non-trivial exponent in [2, q-2]. For large q this is still huge.
    x = secrets.randbelow(q - 3) + 2
    y = pow(g, x, q)
    return x, y


def dh_shared_secret(q: int, private_exponent: int, other_public: int) -> int:
    """Compute the DH shared secret s = (other_public ^ private_exponent) mod q."""
    return pow(other_public, private_exponent, q)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-CBC and PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES-CBC and remove PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def demo_dh(q: int, g: int, label: str) -> None:
    """Run an end-to-end DH + AES-CBC demo for the given parameters."""
    print(f"\n{label}")
    print(f"q (modulus) = {q}")
    print(f"g (generator) = {g}")

    # Alice and Bob each generate DH keypairs.
    xa, ya = dh_keypair(q, g)
    xb, yb = dh_keypair(q, g)

    # Each side computes the shared secret using the other's public value.
    sa = dh_shared_secret(q, xa, yb)
    sb = dh_shared_secret(q, xb, ya)

    # The shared secrets must match.
    assert sa == sb, "DH shared secrets do not match!"

    # Derive the AES-128 key from the shared secret.
    key = derive_aes_key(sa)

    # Assignment allows a shared IV for both directions.
    iv = secrets.token_bytes(16)

    # Alice -> Bob
    c0 = aes_cbc_encrypt(key, iv, b"Hi Bob!")
    m0 = aes_cbc_decrypt(key, iv, c0)

    # Bob -> Alice
    c1 = aes_cbc_encrypt(key, iv, b"Hi Alice!")
    m1 = aes_cbc_decrypt(key, iv, c1)

    # Print small, helpful output for verification.
    print(f"Shared secret s = {sa}")
    print(f"AES-128 key (hex) = {key.hex()}")
    print(f"IV (hex) = {iv.hex()}")
    print(f"Alice -> Bob ciphertext (hex) = {c0.hex()}")
    print(f"Decrypted m0 = {m0!r}")
    print(f"Bob -> Alice ciphertext (hex) = {c1.hex()}")
    print(f"Decrypted m1 = {m1!r}")


def main() -> None:
    demo_dh(TOY_Q, TOY_G, "Task 1, Part 1. Small Parameter Test")
    demo_dh(IETF_1024_Q, IETF_1024_G, "Task 1, Part 2. Real-Life Parameters")


if __name__ == "__main__":
    main()
