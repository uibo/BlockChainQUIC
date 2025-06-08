from random import randint

import rlp
from rlp.sedes import big_endian_int, Binary, binary

class LegacyTransaction(rlp.Serializable):
    fields = [
        ('nonce', big_endian_int),
        ('gas_price', big_endian_int),
        ('gas_limit', big_endian_int),
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]

def make_tx_list(num: int):
    tx_list = []
    for i in range(num):
        tx_list.append(LegacyTransaction(
            nonce=i,
            gas_price=20_000_000_000,
            gas_limit=21000,
            to=bytes.fromhex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            value=1_000_000_000_000_000,
            data=b'',
            v=27,
            r=int("0x1c5e5b7e1b0c9d10d2a7c93ec17e3edb14e06c0e7c6f2445a84f9cb6b7d6f3f3", 16),
            s=int("0x5f74bcd9d8ed5f6014dbf7d7d1ee84adf196e2df6a11a2d32b3b1a3ccf3e5e6b", 16),
        ))
    return tx_list


def split_data(data: tuple, length: int):  # 25MB
    chunks = []
    divisor = 4
    n = length // divisor
    for i in range(0, divisor):
        chunk = data[n*i:n*(i+1)]
        chunks.append(chunk)
    return chunks

tx_amount = 50000
tx_list_array = make_tx_list(tx_amount)
chunks = split_data(tx_list_array, tx_amount)
