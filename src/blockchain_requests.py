"""This module contains functions to query bitcoin nodes. 
Some of these functions request the data from 'https://blockchain.info', 
which provides public endpoints that can be queried without using an API key.
Other functions request the data from 'https://getblock.io', which requires 
an API key. At the time of writing API key for 'getblock.io' can be generated
by subscribing to their free tier, which grants 40k requests per day.
"""

from requests import get, post

BLOCKCHAIN_INFO_HOST = 'https://blockchain.info'
GETBLOCK_HOST = 'https://btc.getblock.io/mainnet'


def get_block_data(block_height):
    """Downloads the information from a bitcoin block

    Args:
        block_height (int): the height of a bitcoin block

    Returns:
        dict: A dictionary with the following three keys: 
            block_hash (string): a hexadecimal string 
            representing the block hash
            merkle_root (string): a hexadecimal string 
            corresponding to the merkle root of the 
            transaction tree for this block
            tx_hashes (list(string)): a list of hexadecimal 
            strings, each of which corresponds to the hash 
            of a transaction included in the block.
    """
    request = f'{BLOCKCHAIN_INFO_HOST}/block-height/{block_height}'
    print(request)
    response = get(request, params={'format': 'json'})
    print(response.status_code)
    block = response.json()['blocks'][0]
    return {
        'block_hash': block['hash'],
        'merkle_root': block['mrkl_root'],
        'tx_hashes': list(map(lambda tx: tx['hash'], block['tx']))
    }


def __parse_next_field(b, start, len, as_int=False):
    (next_field, i) = (bytes.hex(b[start:start+len][::-1]), start+len)
    if (as_int):
        next_field = int(next_field, 16)
    return (next_field, i)


def __parse_compact_size_uint(b, start):
    first_byte = int(bytes.hex(b[start:start+1]), 16)
    if (first_byte < 0xfd):
        # 1 byte used to represent an integer with value less than 0xfd
        int_starts_at = start
        len = 1
    else:
        # multiple bytes used after the first one, the exact number
        # being determined by the int value of the first byte
        int_starts_at = start+1
        if (first_byte == 0xfd):
            len = 2
        elif (first_byte == 0xfe):
            len = 4
        elif (first_byte == 0xff):
            len = 8
    return __parse_next_field(b, int_starts_at, len, as_int=True)


def __parse_flag(b, i, length):
    result = ''
    for j in range(i, i+length):
        current_byte = bytes.hex(b[j:j+1])
        binary = bin(int(current_byte, 16))
        reversed = binary[2:][::-1]
        result += reversed
        to_be_padded = (8 - len(reversed)) % 8
        result += '0' * to_be_padded

    return (result, i+length)


def __decode_merkle_proof(encoded):
    BLOCK_HEADER_FIELD_SIZE = 4
    NTX_FIELD = 4
    HASH_SIZE = 32
    # For some reason that is not completely clear to me, data is returned
    # in reverse order, so we reverse them here
    as_bytes = bytes.fromhex(encoded)

    i = 0
    (block_version, i) = __parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE)
    (prev_block_hash, i) = __parse_next_field(as_bytes, i, HASH_SIZE)
    (merkle_root, i) = __parse_next_field(as_bytes, i, HASH_SIZE)
    (time, i) = __parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (nBits, i) = __parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (nonce, i) = __parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (n_txs, i) = __parse_next_field(as_bytes, i, NTX_FIELD, as_int=True)
    (n_hashes, i) = __parse_compact_size_uint(as_bytes, i)
    hashes = list()
    for j in range(0, n_hashes):
        (hash, i) = __parse_next_field(as_bytes, i, HASH_SIZE)
        hashes.append(hash)
    (flag_size, i) = __parse_compact_size_uint(as_bytes, i)
    (flag, i) = __parse_flag(as_bytes, i, flag_size)
    return {
        'block_version': block_version,
        'previous_block_hash': prev_block_hash,
        'merkle_root': merkle_root,
        'time': time,
        'nBits': nBits,
        'nonce': nonce,
        'number_txs': n_txs,
        'number_of_hashes': n_hashes,
        'hashes': hashes,
        'flag_size': flag_size,
        'flag': flag
    }


def __get_encoded_merkle_proof(tx_hash, block_hash, api_key):
    endpoint = f'{GETBLOCK_HOST}/'
    print(endpoint)
    response = post(
        endpoint,
        headers={
            'x-api-key': api_key,
            'Content-Type': 'application/json'
        },
        json={
            'jsonrpc': '2.0',
            'method': 'gettxoutproof',
            'params': [[tx_hash], block_hash],
            'id': 'getblock.io'
        }
    )
    print(response.status_code)
    return response.json()


def get_decoded_merkle_proof(tx_hash, block_hash, api_key):
    """Requests a merkle proof that the transaction with hash 
    `tx_hash` has been included in the block with hash `block_hash`. 
    It requires a valid `api_key` for querying the bitcoin nodes 
    provided by 'https://btc.getblock.io/mainnet'.

    Args:
        tx_hash (string): the hash of the transaction as a hexadecimal string
        block_hash (string): the hash of the block where the transaction has 
            been included
        api_key (string): a valid api key for querying 
            'https://btc.getblock.io/mainnet'

    Returns:
        dict: A dictionary containing the following keys:
            block_version (string): the version of the block
            previous_block_hash (string): the hash of the previous block
            merkle_root (string): the hash of the root of the merkle 
                tree generated by the transactions included in the block
            time (string): the unix timestamp of when the block was mined
            nBits (string): the size of the block in bits
            nonce (string): the golden nonce used to mine the block
            number_txs (int): the number of transactions in the block
            number_of_hashes (int): the number of hashes included in the 
                merkle proof that the transaction was included in the block
            hashes (list(string)): the hashes of the transactions that are 
                used as part of the merkle proof
            flag_size (int): the size of the flag in bytes
            flag (string): a string of binary digits determining how 
                the transaction hashes of the merke proof must be hashed 
                together to reconstruct the merkle root
    """
    response = __get_encoded_merkle_proof(tx_hash, block_hash, api_key)
    return __decode_merkle_proof(response['result'])
