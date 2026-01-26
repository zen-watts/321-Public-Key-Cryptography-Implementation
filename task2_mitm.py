"""Task 2: Demonstrate DH MITM attacks (key fixing + generator tampering).

This script reuses Task 1 helpers to show that naive DH is vulnerable to
active attackers who modify values in transit.
"""

import secrets

from task1_dh import (
    TOY_G,
    TOY_Q,
    IETF_1024_G,
    IETF_1024_Q,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    derive_aes_key,
    dh_keypair,
    dh_shared_secret,
)


def demo_key_fixing_attack(q: int, g: int, label: str) -> None:
    """Mallory replaces YA/YB with q to force a predictable shared secret."""
    print(f"\n=== {label} ===")
    print("Mallory replaces public values with q (mod q => 0).")

    # Alice and Bob generate legitimate DH public keys.
    xa, ya = dh_keypair(q, g)
    xb, yb = dh_keypair(q, g)

    # Mallory intercepts and replaces both public values with q.
    ya_to_bob = q
    yb_to_alice = q

    # Alice and Bob compute a shared secret with the tampered values.
    sa = dh_shared_secret(q, xa, yb_to_alice)
    sb = dh_shared_secret(q, xb, ya_to_bob)
    assert sa == sb, "Shared secrets should match even under attack."

    # Because q ≡ 0 (mod q), the shared secret is fixed to 0.
    key_ab = derive_aes_key(sa)

    # Use a single IV for both directions.
    iv = secrets.token_bytes(16)

    # Alice and Bob exchange messages using their (compromised) key.
    c0 = aes_cbc_encrypt(key_ab, iv, b"Hi Bob!")
    c1 = aes_cbc_encrypt(key_ab, iv, b"Hi Alice!")

    # Mallory knows the secret is fixed to 0 and can decrypt both messages.
    mallory_key = derive_aes_key(0)
    m0 = aes_cbc_decrypt(mallory_key, iv, c0)
    m1 = aes_cbc_decrypt(mallory_key, iv, c1)

    print(f"Computed shared secret s = {sa}")
    print(f"AES-128 key (hex) = {key_ab.hex()}")
    print(f"Mallory decrypted m0 = {m0!r}")
    print(f"Mallory decrypted m1 = {m1!r}")


def mallory_secret_from_tampered_g(q: int, g_tampered: int, ya: int, yb: int) -> int:
    """Derive the shared secret given Mallory's tampered generator.

    - g = 1  => all public values are 1, so s = 1.
    - g = q  => g ≡ 0 (mod q), so all public values are 0, so s = 0.
    - g = q-1 => public values are 1 or q-1 depending on exponent parity.
                If either public value is 1, the secret is 1; otherwise q-1.
    """
    if g_tampered == 1:
        return 1
    if g_tampered == q:
        return 0
    if g_tampered == q - 1:
        if ya == 1 or yb == 1:
            return 1
        return q - 1
    raise ValueError("Unexpected tampered generator value")


def demo_generator_attack(q: int, g_tampered: int, label: str) -> None:
    """Mallory tampers with the generator g and then decrypts messages."""
    print(f"\n=== {label} ===")
    print(f"Mallory changes g to {g_tampered}.")

    # Alice and Bob unknowingly use the tampered generator.
    xa, ya = dh_keypair(q, g_tampered)
    xb, yb = dh_keypair(q, g_tampered)

    sa = dh_shared_secret(q, xa, yb)
    sb = dh_shared_secret(q, xb, ya)
    assert sa == sb, "Shared secrets should match even under attack."

    key_ab = derive_aes_key(sa)
    iv = secrets.token_bytes(16)

    c0 = aes_cbc_encrypt(key_ab, iv, b"Hi Bob!")
    c1 = aes_cbc_encrypt(key_ab, iv, b"Hi Alice!")

    # Mallory computes the shared secret from the tampered generator and publics.
    mallory_s = mallory_secret_from_tampered_g(q, g_tampered, ya, yb)
    mallory_key = derive_aes_key(mallory_s)

    m0 = aes_cbc_decrypt(mallory_key, iv, c0)
    m1 = aes_cbc_decrypt(mallory_key, iv, c1)

    print(f"Public YA = {ya}")
    print(f"Public YB = {yb}")
    print(f"Computed shared secret s = {sa}")
    print(f"Mallory's derived secret s = {mallory_s}")
    print(f"Mallory decrypted m0 = {m0!r}")
    print(f"Mallory decrypted m1 = {m1!r}")


def main() -> None:
    """Run Task 2A and Task 2B demos for toy and IETF parameters."""
    # Task 2A: replace YA/YB with q (key-fixing attack).
    demo_key_fixing_attack(TOY_Q, TOY_G, "Task 2A: Key-fixing attack (toy)")
    demo_key_fixing_attack(IETF_1024_Q, IETF_1024_G, "Task 2A: Key-fixing attack (IETF 1024-bit)")

    # Task 2B: generator tampering with g = 1, q, q-1.
    for g_tampered in (1, TOY_Q, TOY_Q - 1):
        demo_generator_attack(TOY_Q, g_tampered, f"Task 2B: Generator tampering (toy, g={g_tampered})")

    for g_tampered in (1, IETF_1024_Q, IETF_1024_Q - 1):
        demo_generator_attack(
            IETF_1024_Q,
            g_tampered,
            f"Task 2B: Generator tampering (IETF 1024-bit, g={g_tampered})",
        )


if __name__ == "__main__":
    main()
