from hashlib import sha256


def bsha256(bytes):
    return sha256(bytes).digest()


def dsha256(bytes):
    return bsha256(bsha256(bytes))


def concat_dsha256(left, right):
    return dsha256((right + left)[::-1])[::-1]


def compute_merkle_root_aux(hashes, n):
    if (n == 1):
        return hashes[0]
    else:
        for i in range(0, n, 2):
            left = hashes[i]
            right = hashes[min(i + 1, n-1)]
            hashes[i // 2] = concat_dsha256(left, right)
        return compute_merkle_root_aux(hashes, ((n + 1) // 2))


def compute_merkle_root(hashes):
    hashes = list(map(lambda x: bytes.fromhex(x), hashes))
    return bytes.hex(compute_merkle_root_aux(hashes.copy(), len(hashes)))
