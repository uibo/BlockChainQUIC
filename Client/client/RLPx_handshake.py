import asyncio
from coincurve import PrivateKey, PublicKey
from ecies import encrypt, decrypt
from random import randbytes
from eth_utils import keccak

def make_component():
    ephe_priv = PrivateKey()  # ECDSA 상에서 32 byte 개인키
    ephe_pub = ephe_priv.public_key.format(compressed=False)  # 65바이트 uncompressed prefix 0x04
    nonce = randbytes(32)
    version = b"\x04"
    return ephe_priv, ephe_pub, nonce, version

def KDF(ecdh_shared_secret: bytes, initiator_nonce: bytes, recipient_nonce: bytes):
    assert len(ecdh_shared_secret) == 32
    assert len(initiator_nonce) == 32
    assert len(recipient_nonce) == 32

    shared_secret = keccak(ecdh_shared_secret)              # Step 1
    key_material = keccak(shared_secret + initiator_nonce + recipient_nonce)  # Step 2

    aes_secret = key_material[:16]
    mac_secret = key_material[16:]
    return aes_secret, mac_secret

async def handshake_initiator(static_priv: PrivateKey, peer_pub: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # 1) EPH key + nonce + version 준비
    ephe_priv, ephe_pub, nonce, version = make_component()

    # 2) 서명 → auth_msg 조립
    signature = static_priv.sign_recoverable(ephe_pub, hasher=keccak)
    auth_msg = signature + ephe_pub + nonce + version

    # 3) 암호화 후 전송
    enc_auth = encrypt(peer_pub, auth_msg)
    writer.write(enc_auth)
    await writer.drain()

    # 4) ACK 수신 → 복호화
    enc_ack = await reader.read(1024)  # 충분히 큰 버퍼
    ack = decrypt(static_priv.to_hex(), enc_ack)
    recv_ephe_pub = ack[:65]
    recv_nonce    = ack[65:97]
    assert ack[97:98] == version

    # 5) 키 도출
    ecdh = ephe_priv.ecdh(recv_ephe_pub)
    aes_sec, mac_sec = KDF(ecdh, nonce, recv_nonce)
    return aes_sec, mac_sec

async def handshake_receiver(static_priv: PrivateKey, peers: list[tuple], reader: asyncio.StreamReader, writer: asyncio.StreamWriter,):
    # 1) EPH key + nonce + version 준비
    ephe_priv, ephe_pub, nonce, version = make_component()

    # 2) auth_msg 수신 → 복호화
    enc_auth = await reader.read(1024)
    auth    = decrypt(static_priv.to_hex(), enc_auth)
    sig     = auth[:65]
    init_pub = auth[65:130]
    init_nonce = auth[130:162]
    assert auth[162:163] == version

    # 3) 서명 검증을 통해 peer 식별
    signer = PublicKey.from_signature_and_message(sig, init_pub, hasher=keccak).format(compressed=False)
    # peers는 (host,port,static_pub(bytes)) 리스트여야 함
    if signer not in [p[2] for p in peers]:
        raise Exception("Unknown peer")

    # 4) ACK 조립·암호화·전송
    ack_msg = ephe_pub + nonce + version
    enc_ack = encrypt(signer, ack_msg)
    writer.write(enc_ack)
    await writer.drain()

    # 5) 키 도출
    ecdh = ephe_priv.ecdh(init_pub)
    aes_sec, mac_sec = KDF(ecdh, init_nonce, nonce)
    return aes_sec, mac_sec