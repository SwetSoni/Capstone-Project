"""
Secure Password Hashing Module — Bcrypt Implementation
Capstone Part 3 — Task 3: Secure Password Hashing

This module provides:
- hash_password(): Generates a Bcrypt hash with a unique salt
- verify_password(): Verifies a plaintext password against a stored hash

Why Bcrypt over MD5:
- MD5 is a fast hashing algorithm designed for checksums, NOT passwords.
  Its speed means an attacker can compute billions of MD5 hashes per second
  using GPU-accelerated brute-force tools (e.g., Hashcat).
- MD5 has known collision vulnerabilities (two different inputs can produce
  the same hash), making it cryptographically broken.
- MD5 does not incorporate a salt by default, making it vulnerable to
  precomputed rainbow table attacks — an attacker can look up common
  password hashes in a table without any computation.
- Bcrypt addresses ALL three weaknesses:
  1. It is intentionally slow (adaptive cost factor) — each hash computation
     takes ~100ms instead of nanoseconds, making brute-force impractical.
  2. It automatically generates a unique random salt for every hash,
     so identical passwords produce different hashes (defeating rainbow tables).
  3. The cost factor can be increased over time as hardware gets faster,
     keeping the algorithm resistant to future brute-force attacks.
"""

import bcrypt


def hash_password(plain_text: str) -> str:
    """
    Hash a plaintext password using Bcrypt with a unique random salt.

    Args:
        plain_text: The plaintext password to hash.

    Returns:
        The Bcrypt hash string (includes the salt, cost factor, and hash).
    """
    # Generate a unique random salt (default rounds=12)
    # Each call produces a different salt, so the same password
    # will produce a different hash every time
    salt = bcrypt.gensalt(rounds=12)

    # Hash the password with the generated salt
    # The password must be encoded to bytes before hashing
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)

    # Return the hash as a UTF-8 string for storage in the database
    return hashed.decode("utf-8")


def verify_password(plain_text: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored Bcrypt hash.

    Args:
        plain_text: The plaintext password to verify.
        stored_hash: The stored Bcrypt hash string from the database.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    # bcrypt.checkpw extracts the salt from the stored hash and
    # re-hashes the plaintext with the same salt, then compares
    return bcrypt.checkpw(
        plain_text.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


# ============================================================
# DEMONSTRATION — Proving unique salts produce different hashes
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Bcrypt Password Hashing Demonstration")
    print("=" * 60)

    test_password = "SecureP@ssw0rd123"

    # Hash the same password twice
    hash1 = hash_password(test_password)
    hash2 = hash_password(test_password)

    print(f"\nPassword:  {test_password}")
    print(f"Hash 1:    {hash1}")
    print(f"Hash 2:    {hash2}")
    print(f"\nHashes are different (unique salts): {hash1 != hash2}")

    # Verify both hashes match the original password
    print(f"\nVerify Hash 1: {verify_password(test_password, hash1)}")
    print(f"Verify Hash 2: {verify_password(test_password, hash2)}")

    # Verify a wrong password does NOT match
    print(f"Verify wrong password: {verify_password('WrongPassword', hash1)}")

    print("\n" + "=" * 60)
    print("This proves that Bcrypt generates a unique salt for each")
    print("hash operation — the same input produces different outputs,")
    print("defeating rainbow table attacks.")
    print("=" * 60)
