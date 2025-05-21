from coincurve import PrivateKey, PublicKey
import socket
from random import randbytes
from eth_utils import keccak

def make_shared_secret_by_initiator(conn: socket.socket):
    ephemeral_priv = PrivateKey()
    ephemeral_pub_bytes = ephemeral_priv.public_key.format(compressed=False)[1:]
    nonce = randbytes(32)
    msg = keccak(ephemeral_pub_bytes)
    signature = ephemeral_priv.sign_recoverable(msg)
    version = b"\x04"
    auth_msg = signature + ephemeral_pub_bytes + nonce + version
    conn.send(auth_msg)
    ack_msg = conn.recv(97)
    receiver_pub_key = ack_msg[:64]
    shared_secret = ephemeral_priv.ecdh(b'\x04' + receiver_pub_key)
    print(shared_secret)


def make_shared_secret_by_receiver(conn: socket.socket):
    auth_msg = conn.recv(162)
    signature = auth_msg[:65]
    initiator_pub_key = auth_msg[65:129]
    msg = keccak(auth_msg[65:129])
    signer = PublicKey.from_signature_and_message(signature, msg).format(compressed=False)
    print(signer[1:] == initiator_pub_key)
    ephemeral_priv = PrivateKey()
    ephemeral_pub_bytes = ephemeral_priv.public_key.format(compressed=False)[1:]
    nonce = randbytes(32)
    version = b"\x04"
    ack_msg = ephemeral_pub_bytes + nonce + version
    conn.send(ack_msg)
    print(ephemeral_priv.ecdh(signer))