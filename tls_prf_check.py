import hashlib
import hmac


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def tls_prf_sha256(secret, label, seed, length):
    """
    TLS 1.2 PRF using HMAC-SHA256.

    PRF(secret, label, seed) = P_SHA256(secret, label || seed)
    """

    label_seed = label + seed

    # A(0) = label || seed
    a = label_seed

    output = bytearray()

    while len(output) < length:

        # A(i) = HMAC(secret, A(i-1))
        a = hmac_sha256(secret, a)

        # HMAC(secret, A(i) || label || seed)
        block = hmac_sha256(secret, a + label_seed)

        output.extend(block)

    return bytes(output[:length])


def check(name, actual, expected):
    actual = actual.upper()
    expected = expected.upper()

    print(f"{name}=" + actual)

    if actual == expected:
        print(f"{name}: PASS")
    else:
        print(f"{name}: FAIL")
        print("EXPECTED=" + expected)
        print("ACTUAL  =" + actual)


# ============================================================
# INPUTS FROM ARDUINO
# ============================================================

ecdhe_shared_secret = bytes.fromhex(
    "13C7B38BA40E7C6FFDED5A8B2F20EFEBFD6FF44630EDDF4E7097E72C16E829CD"
)

client_random = bytes.fromhex(
    "000102030405060708090A0B0C0D0E0F"
    "101112131415161718191A1B1C1D1E1F"
)

server_random = bytes.fromhex(
    "6A9F3E2FCD5AA7607732180C03F7062B"
    "78BA0390BE16334E444F574E47524401"
)


# ============================================================
# 1. MASTER SECRET
# ============================================================

master_seed = client_random + server_random

master_secret = tls_prf_sha256(
    ecdhe_shared_secret,
    b"master secret",
    master_seed,
    48
)

print("MASTER_SEED=" + master_seed.hex().upper())
print("MASTER_SECRET=" + master_secret.hex().upper())


# ============================================================
# 2. KEY EXPANSION
# ============================================================

key_expansion_seed = server_random + client_random

key_block = tls_prf_sha256(
    master_secret,
    b"key expansion",
    key_expansion_seed,
    40
)

print("KEY_EXPANSION_SEED=" + key_expansion_seed.hex().upper())
print("KEY_BLOCK=" + key_block.hex().upper())


# ============================================================
# 3. SPLIT KEY BLOCK
# ============================================================

client_write_key = key_block[0:16]
server_write_key = key_block[16:32]
client_write_iv = key_block[32:36]
server_write_iv = key_block[36:40]

print("CLIENT_WRITE_KEY=" + client_write_key.hex().upper())
print("SERVER_WRITE_KEY=" + server_write_key.hex().upper())
print("CLIENT_WRITE_IV=" + client_write_iv.hex().upper())
print("SERVER_WRITE_IV=" + server_write_iv.hex().upper())


# ============================================================
# EXPECTED ARDUINO OUTPUT
# ============================================================

expected_master_secret = (
    "DA609992D82E5B50CDA3D6F1D7F71022"
    "CD4AE484A2834A0A5AD8754053D1A2ED"
    "899E350D7522F181AE4C0037B96716EC"
)

expected_key_block = (
    "98ADCC656E0D658BAE3C2DBC7C5AE1F4"
    "23BC09F591C04A0B027DD312BC2ACB1A"
    "ADA8AC11B9DC5F23"
)


# ============================================================
# 4. VERIFY AGAINST ARDUINO
# ============================================================

print()
print("========== VERIFICATION ==========")

check(
    "MASTER_SECRET",
    master_secret.hex(),
    expected_master_secret
)

check(
    "KEY_BLOCK",
    key_block.hex(),
    expected_key_block
)


print()
print("========== DONE ==========")

