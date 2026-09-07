from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xor_block(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gf_mul(x, y):
    # Same bit ordering/reduction as your Arduino gcmMultiply()
    result = bytearray(16)
    v = bytearray(y)

    for i in range(128):
        bit = (x[i >> 3] >> (7 - (i & 7))) & 1

        if bit:
            for j in range(16):
                result[j] ^= v[j]

        lsb = v[15] & 1

        for j in range(15, 0, -1):
            v[j] = ((v[j] >> 1) | ((v[j - 1] & 1) << 7))

        v[0] >>= 1

        if lsb:
            v[0] ^= 0xE1

    return bytes(result)


def ghash(h, aad, ciphertext):
    y = bytes(16)

    def hash_block(block):
        nonlocal y
        y = gf_mul(xor_block(y, block), h)

    # AAD
    for i in range(0, len(aad), 16):
        block = aad[i:i + 16]
        if len(block) < 16:
            block += bytes(16 - len(block))
        hash_block(block)

    # Ciphertext
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        if len(block) < 16:
            block += bytes(16 - len(block))
        hash_block(block)

    # Length block:
    # 64-bit AAD length in bits || 64-bit ciphertext length in bits
    length_block = (
        (len(aad) * 8).to_bytes(8, "big") +
        (len(ciphertext) * 8).to_bytes(8, "big")
    )

    hash_block(length_block)

    return y


def aes_ecb(key, block):
    enc = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).encryptor()

    return enc.update(block) + enc.finalize()


key = bytes.fromhex(
    "E901E8CD3A923358AB3C5B6C79DF47C7"
)

j0 = bytes.fromhex(
    "EFD2B1FA000000000000000000000001"
)

aad = bytes.fromhex(
    "00000000000000001603030010"
)

ct = bytes.fromhex(
    "8D579051A97CEE7BF2AB89CE4E95A5B0"
)

# H = AES(K, 0^128)
h = aes_ecb(key, bytes(16))

print("H    =", h.hex().upper())

# GHASH(H, AAD, ciphertext)
s = ghash(h, aad, ct)

print("GHASH=", s.hex().upper())

# Tag = AES(K, J0) XOR GHASH
e_j0 = aes_ecb(key, j0)
tag = xor_block(e_j0, s)

print("EJ0  =", e_j0.hex().upper())
print("TAG  =", tag.hex().upper())