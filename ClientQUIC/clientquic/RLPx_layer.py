import asyncio
from coincurve import PrivateKey, PublicKey
from ecies import encrypt, decrypt
from random import randbytes
from eth_utils import keccak
import rlp

STATIC_PRIV = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
]

STATIC_PUBL = [
    STATIC_PRIV[0].public_key.format(compressed=False),
    STATIC_PRIV[1].public_key.format(compressed=False),
]

class RLPx_layer():
    def __init__(self, mine: int, counterpart: int):
        self.mine = {
            "static_priv": STATIC_PRIV[mine],
            "static_publ": STATIC_PUBL[mine],
            "ephe_priv" : None,
            "ephe_publ": None,
            "nonce": None,
            "version": None
        }
        self.counterpart = {
            "static_publ": STATIC_PUBL[counterpart],
            "ephe_priv" : None,
            "ephe_publ": None,
            "nonce": None,
            "version": None
        }
        self.peer = {}
        self.peers = STATIC_PUBL

        # --- RLPx 암호화/복호화에 사용할 키 및 시퀀스 카운터 ---
        self.aes_sec = None
        self.mac_sec = None
        self.egress_seq = 0
        self.ingress_seq = 0

    def make_component(self):
        self.mine["ephe_priv"] = PrivateKey()  # ECDSA 상에서 32 byte 개인키
        self.mine["ephe_publ"] = self.mine["ephe_priv"].public_key.format(compressed=False)  # 65바이트 uncompressed prefix 0x04
        self.mine["nonce"] = randbytes(32)
        self.mine["version"] = b"\x04"

    def KDF(self, num=0):
        ecdh = self.mine["ephe_priv"].ecdh(self.counterpart["ephe_publ"])
        shared_secret = keccak(ecdh)
        if num == 0:
            key_material = keccak(shared_secret + self.mine["nonce"] + self.counterpart["nonce"])  # Step 2
        else:
            key_material = keccak(shared_secret + self.counterpart["nonce"] + self.mine["nonce"])  # Step 2

        self.aes_sec = key_material[:16]
        self.mac_sec = key_material[16:]

    def handshake_initiator1(self):
    # 1) EPH key + nonce + version 준비
        self.make_component()

        # 2) 서명 → auth_msg 조립
        signature = self.mine["static_priv"].sign_recoverable(self.mine["ephe_publ"], hasher=keccak)
        auth_msg = signature + self.mine["ephe_publ"] + self.mine["nonce"] + self.mine["version"]

        # 3) 암호화 후 전송
        enc_auth = encrypt(self.counterpart["static_publ"], auth_msg)
        return enc_auth
    
    def handshake_initiator2(self, enc_ack):
        # 4) ACK 수신 → 복호화
        ack = decrypt(self.mine["static_priv"].to_hex(), enc_ack)
        self.counterpart["ephe_publ"] = ack[:65]
        self.counterpart["nonce"]    = ack[65:97]
        assert ack[97:98] == self.mine["version"]

        # 5) 키 도출
        self.KDF(1)

    def handshake_receiver(self, enc_auth):
        # 1) EPH key + nonce + version 준비
        self.make_component()

        # 2) auth_msg 수신 → 복호화
        auth    = decrypt(self.mine["static_priv"].to_hex(), enc_auth)
        sig     = auth[:65]
        self.counterpart["ephe_publ"] = auth[65:130]
        self.counterpart["nonce"] = auth[130:162]
        assert auth[162:163] == self.mine["version"]

        # 3) 서명 검증을 통해 peer 식별
        signer = PublicKey.from_signature_and_message(sig, self.counterpart["ephe_publ"], hasher=keccak).format(compressed=False)
        # peers는 node_id 리스트
        if signer not in [id for id in self.peers]:
            raise Exception("Unknown peer")

        # 4) ACK 조립·암호화·전송
        ack_msg = self.mine["ephe_publ"] + self.mine["nonce"] + self.mine["version"]
        enc_ack = encrypt(signer, ack_msg)
        self.KDF(0)
        return enc_ack
    
    def pack_tx_list(self, tx_list: list[rlp.Serializable]) -> bytes:
        """
        - tx_list: rlp.Serializable을 상속한 LegacyTransaction 객체들의 리스트
        - 리턴값: RLPx framing·암호화가 완료된 '바이트'
        """
        if self.aes_sec is None or self.mac_sec is None:
            raise Exception("pack_tx_list: AES 혹은 MAC 키가 설정되지 않았습니다.")

        # 1) RLP 직렬화: tx_list 전체
        payload = rlp.encode(tx_list)

        return payload

    def unpack_tx_list(self, payload: bytes):
        """
        - frame: pack_tx_list()가 반환한 전체 프레임 바이트
        - 리턴값: rlp.decode(...) 결과 (tx_list를 그대로 복원한 Python 리스트)
        """
        if self.aes_sec is None or self.mac_sec is None:
            raise Exception("unpack_tx_list: AES 혹은 MAC 키가 설정되지 않았습니다.")

        tx_list = rlp.decode(payload)

        return tx_list