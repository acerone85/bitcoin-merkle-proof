from hashlib import sha256


def __bsha256(bytes):
    return sha256(bytes).digest()


def __dsha256(bytes):
    return __bsha256(__bsha256(bytes))


def concat_dsha256(left, right):
    return __dsha256((right + left)[::-1])[::-1]


def __compute_merkle_root(hashes, n):
    if (n == 1):
        return hashes[0]
    else:
        for i in range(0, n, 2):
            left = hashes[i]
            right = hashes[min(i + 1, n-1)]
            hashes[i // 2] = concat_dsha256(left, right)
        return __compute_merkle_root(hashes, ((n + 1) // 2))


def compute_merkle_root(hashes):
    """Generates the merkle root of the tree whose leaves are the transaction
    hashes given in input. The transaction hashes are usually the transaction 
    hashes listed in a bitcoin. For example, for any valid `block height`, the 
    following invariant should hold:
    ```
    from blockchain_requests import get_block_data
    block = get_block_data(block_height)
    assert (compute_merkle_root(block['tx_hashes']) == block['merkle_root'])
    ```
    Args:
        hashes (list(string)): The list of transactions hashes of a bitcoin 
        block, in the order they appear in the block

    Returns:
        string: the hash (as an hexadecimal string) of the merkle root computed
        from the list of transactions given in input.
    """
    hashes = list(map(lambda x: bytes.fromhex(x), hashes))
    return bytes.hex(__compute_merkle_root(hashes.copy(), len(hashes)))
