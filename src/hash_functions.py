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


def verify_merkle_proof_aux(tx_hash, merkle_proof, tx_index):
    if len(merkle_proof) == 0:
        return tx_hash
    else:
        if (tx_index % 2 == 0):
            (left, right) = (tx_hash, merkle_proof[0])
        else:
            (left, right) = (merkle_proof[0], tx_hash)

        return verify_merkle_proof_aux(
            concat_dsha256(left, right),
            merkle_proof[1::],
            tx_index/2
        )


def verify_merkle_proof(merkle_root, merkle_proof, tx_index):
    merkle_proof_as_bytes = list(map(lambda x: bytes.fromhex(x), merkle_proof))
    computed_merkle_root = bytes.hex(verify_merkle_proof_aux(
        merkle_proof_as_bytes[0],
        merkle_proof_as_bytes[1::],
        tx_index
    ))
    print(f'Actual merkle root: {merkle_root}')
    print(f'Computed merkle root: {computed_merkle_root}')
    return merkle_root == computed_merkle_root
