import re
from requests import get, post

BLOCKCHAIN_INFO_HOST = 'https://blockchain.info'
GETBLOCK_HOST = 'https://btc.getblock.io/mainnet'


def get_block_data(block_height):
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


def parse_next_field(b, start, len, as_int=False):
    (next_field, i) = (bytes.hex(b[start:start+len][::-1]), start+len)
    if (as_int):
        next_field = int(next_field, 16)
    return (next_field, i)


def parse_compact_size_uint(b, start):
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
    return parse_next_field(b, int_starts_at, len, as_int=True)


def parse_flag(b, i, length):
    result = ''
    for j in range(i, i+length):
        current_byte = bytes.hex(b[j:j+1])
        binary = bin(int(current_byte, 16))
        reversed = binary[2:][::-1]
        result += reversed
        to_be_padded = (8 - len(reversed)) % 8
        result += '0' * to_be_padded

    return (result, i+length)


def decode_merkle_proof(encoded):
    BLOCK_HEADER_FIELD_SIZE = 4
    NTX_FIELD = 4
    HASH_SIZE = 32
    # For some reason that is not completely clear to me, data is returned
    # in reverse order, so we reverse them here
    as_bytes = bytes.fromhex(encoded)

    i = 0
    (block_version, i) = parse_next_field(as_bytes, i, BLOCK_HEADER_FIELD_SIZE)
    (prev_block_hash, i) = parse_next_field(as_bytes, i, HASH_SIZE)
    (merkle_root, i) = parse_next_field(as_bytes, i, HASH_SIZE)
    (time, i) = parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (nBits, i) = parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (nonce, i) = parse_next_field(
        as_bytes, i, BLOCK_HEADER_FIELD_SIZE, as_int=True
    )
    (n_txs, i) = parse_next_field(as_bytes, i, NTX_FIELD, as_int=True)
    (n_hashes, i) = parse_compact_size_uint(as_bytes, i)
    hashes = list()
    for j in range(0, n_hashes):
        (hash, i) = parse_next_field(as_bytes, i, HASH_SIZE)
        hashes.append(hash)
    (flag_size, i) = parse_compact_size_uint(as_bytes, i)
    (flag, i) = parse_flag(as_bytes, i, flag_size)
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


def get_encoded_merkle_proof(tx_hash, block_hash, api_key):
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
    response = get_encoded_merkle_proof(tx_hash, block_hash, api_key)
    return decode_merkle_proof(response['result'])
