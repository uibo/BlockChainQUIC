import asyncio
from coincurve import PrivateKey, PublicKey
from random import randbytes
from eth_utils import keccak


def make_ephemeral_nonce_version():
    ephe_priv = PrivateKey() # ECDSA 상에서 32 byte 개인키
    ephe_pub = ephe_priv.public_key.format(compressed=False)
    nonce = randbytes(32)
    version = b"\x04"
    return ephe_priv, ephe_pub, nonce, version

def derive_rlpx_keys(ecdh_shared_secret: bytes, initiator_nonce: bytes, recipient_nonce: bytes):
    assert len(ecdh_shared_secret) == 32
    assert len(initiator_nonce) == 32
    assert len(recipient_nonce) == 32

    shared_secret = keccak(ecdh_shared_secret)  # Step 1
    key_material_input = shared_secret + initiator_nonce + recipient_nonce
    key_material = keccak(key_material_input)   # Step 2

    aes_secret = key_material[:16]
    mac_secret = key_material[16:]
    
    return aes_secret, mac_secret

async def make_shared_secret_by_receiver(reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter):
    ephe_priv, ephe_pub, nonce, version = make_partial_msg()
    auth_msg = await reader.readexactly(163)
    signature = auth_msg[:65]
    initiator_ephe_pub = auth_msg[65:130]
    initiator_nonce = auth_msg[130:162]
    initiator_version = auth_msg[162:163]
    assert initiator_version == version
    signer = PublicKey.from_signature_and_message(signature, keccak(initiator_ephe_pub), hasher=None).format(compressed=False).hex()
    for NODE in config.nodes.NODE_STATE.KNOWN_NODES:
        if NODE["node_id"] == signer:
            ack_msg = ephe_pub + nonce + version
            writer.write(ack_msg)
            await writer.drain()
            ecdh = ephe_priv.ecdh(initiator_ephe_pub)
            aes_secret, mac_secret = derive_rlpx_keys(ecdh, initiator_nonce, nonce)
            return aes_secret, mac_secret
        else:
            raise Exception

async def make_secret_by_initiator(static_priv: PrivateKey,
                                           reader: asyncio.StreamReader,
                                           writer: asyncio.StreamWriter):
    ephe_priv, ephe_pub, nonce, version = make_ephemeral_nonce_version()
    msg = keccak(ephe_pub)
    signature = static_priv.sign_recoverable(msg, hasher=None)
    auth_msg = signature + ephe_pub + nonce + version

    writer.write(auth_msg)
    await writer.drain()

    ack_msg = await reader.readexactly(98)
    receiver_ephe_pub = ack_msg[:65]
    receiver_nonce = ack_msg[65:97]
    receiver_version = ack_msg[97:98]
    assert receiver_version == version

    ecdh = ephe_priv.ecdh(receiver_ephe_pub)
    aes_secret, mac_secret = derive_rlpx_keys(ecdh, nonce, receiver_nonce)
    return aes_secret, mac_secret