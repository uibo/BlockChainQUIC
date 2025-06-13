from random import randbytes
import time

from coincurve import PrivateKey, PublicKey
from ecies import encrypt, decrypt
from aioquic.quic.connection import QuicConnection
from eth_utils import keccak as keccak256
from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Util import Counter
import rlp

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class RLPx_Layer():
    def __init__(self, _quic: QuicConnection):
        self.ephe_private_key = None
        self.ephe_public_key = None
        self.nonce = None
        self.version = b"\x04"
        self._quic = _quic
        self.aes_secret = None
        self.mac_secret = None
        self.egress_mac = None
        self.ingress_mac = None

    def set_ephemeral_key_and_nonce(self):
        self.ephe_private_key = PrivateKey()  # ECDSA 상에서 32 byte 개인키
        self.ephe_public_key = self.ephe_private_key.public_key.format(compressed=False)  # 65바이트 uncompressed prefix 0x04
        self.nonce = randbytes(32)

    def make_auth_body(self, private_key: PrivateKey):
        signature = private_key.sign_recoverable(self.ephe_public_key, hasher=keccak256)
        return signature + self.ephe_public_key + self.nonce + self.version
    
    def set_auth_mac(self, recipient_nonce: bytes, auth: bytes):
        return keccak.new(data=(xor_bytes(self.mac_secret, recipient_nonce) + auth), digest_bytes=32, update_after_digest=True)

    def set_ack_mac(self, initiator_nonce: bytes, ack: bytes):
        return keccak.new(data=(xor_bytes(self.mac_secret, initiator_nonce) + ack), digest_bytes=32, update_after_digest=True)
    
    def set_RLPx_session_initiator1(
            self, 
            private_key: PrivateKey, 
            peer: tuple[str, int, PublicKey],
        ) -> None:
        print(f"start handshake: {time.time()}")
        self.set_ephemeral_key_and_nonce()
        auth_body = self.make_auth_body(private_key)

        enc_auth_body = encrypt(peer[2], auth_body)
        auth = len(enc_auth_body).to_bytes(2, 'big') + enc_auth_body
        self._quic.send_stream_data(0, auth)
        self.egress_mac = auth
    
    def set_RLPx_session_initiator2(
            self, 
            private_key: PrivateKey, 
            ack: bytes
        ) -> None:
        enc_ack_body = ack[2:]
        ack_body = decrypt(private_key.to_hex(), enc_ack_body)
        recipient_pubk = ack_body[:65]
        recipient_nonce    = ack_body[65:97]
        if ack_body[97:98] == self.version: pass


        ephemeral_key = self.ephe_private_key.ecdh(recipient_pubk)
        shared_secret = keccak256(ephemeral_key + keccak256(recipient_nonce + self.nonce))
        self.aes_secret = keccak256(ephemeral_key + shared_secret)
        self.mac_secret = keccak256(ephemeral_key + self.aes_secret)
        self.egress_mac = self.set_auth_mac(recipient_nonce, self.egress_mac)
        self.ingress_mac = self.set_ack_mac(self.nonce, ack)
        print("setting complete [aes, mac, engress, ingress]")

    def set_RLPx_session_recipient(
            self,
            private_key: PrivateKey,
            peers: list[tuple[str, int, PublicKey]],
            auth: bytes,
        )-> None:
        print(f"start handshake: {time.time()}")
        enc_auth_body = auth[2:]
        auth_body = decrypt(private_key.to_hex(), enc_auth_body)
        sig        = auth_body[:65]
        initiator_pubk   = auth_body[65:130]
        initiator_nonce = auth_body[130:162]
        if auth_body[162:163] == self.version: pass

        signer = PublicKey.from_signature_and_message(sig, initiator_pubk, hasher=keccak256).format(compressed=False)
        if signer not in [p[2] for p in peers]:
            raise Exception("Unknown peer")

        self.set_ephemeral_key_and_nonce()
        ack_body = self.ephe_public_key + self.nonce + self.version
        enc_ack_body = encrypt(signer, ack_body)
        ack = len(enc_ack_body).to_bytes(2, 'big') + enc_ack_body
        self._quic.send_stream_data(0, ack)

        ephemeral_key = self.ephe_private_key.ecdh(initiator_pubk)
        shared_secret = keccak256(ephemeral_key + keccak256(self.nonce + initiator_nonce))
        self.aes_secret = keccak256(ephemeral_key + shared_secret)
        self.mac_secret = keccak256(ephemeral_key + self.aes_secret)
        self.egress_mac = self.set_ack_mac(initiator_nonce, ack)
        self.ingress_mac = self.set_auth_mac(self.nonce, auth)
        print("setting complete [aes, mac, engress, ingress]")

    def handshake_initiator(self) -> None:
        frame = self.ready_to_send(b'HELLO')
        self._quic.send_stream_data(4, frame)

    def handshake_recepient(self)-> None:
        frame = self.ready_to_send(b'HELLO')
        self._quic.send_stream_data(1, frame)

    def ready_to_send(self, msg):
        return self.framing(self.encode_rlp(msg))
    
    def ready_to_receive(self, frame):
        return self.decode_rlp(self.deframing(frame))
    
    def encode_rlp(self, msg):
        return rlp.encode(msg)
    
    def decode_rlp(self, bytes: bytes):
        return rlp.decode(bytes)

    def framing(self, frame_data: bytes):
        aes_header_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        aes_frame_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        mac_cipher = AES.new(self.mac_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        # frame_ciphertext
        pad_len = (16 - (len(frame_data) % 16)) % 16
        frame_plaintext = frame_data + b'\x00' * pad_len
        frame_ciphertext = aes_frame_cipher.encrypt(frame_plaintext)
        frame_size = len(frame_data).to_bytes(3, 'big')


        header_data = frame_size + b'\x00' + b'\x00'
        pad_len = 16 - (len(header_data) % 16)
        header_plaintext = header_data + b'\x00' * pad_len
        header_ciphertext = aes_header_cipher.encrypt(header_plaintext)

        # header_mac
        mac_digest1 = self.egress_mac.digest()[:16]
        header_mac_seed = xor_bytes(mac_cipher.encrypt(mac_digest1), header_ciphertext)
        self.egress_mac.update(header_mac_seed)
        header_mac = self.egress_mac.digest()[:16]

        # frame-mac
        self.egress_mac.update(frame_ciphertext)
        mac_digest2 = self.egress_mac.digest()[:16]
        frame_mac_seed = xor_bytes(mac_cipher.encrypt(mac_digest2), mac_digest2)
        self.egress_mac.update(frame_mac_seed)
        frame_mac = self.egress_mac.digest()[:16]
        return header_ciphertext + header_mac + frame_ciphertext + frame_mac
    
    def deframing(self, frame: bytes) -> bytes:
        header_ciphertext = frame[:16]
        header_mac        = frame[16:32]
        frame_ciphertext  = frame[32:-16]
        frame_mac         = frame[-16:]
        aes_header_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        aes_frame_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        mac_cipher = AES.new(self.mac_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))

        # (2-1) egress_mac.digest()와 대응하기 위해, 현재 ingress_mac 상태에서 digest()
        mac_digest1 = self.ingress_mac.digest()[:16]

        # (2-2) framing()과 동일하게 header_mac_seed 계산
        #        header_mac_seed = AES-CBC(mac_digest1) xor header_ciphertext
        header_mac_seed = xor_bytes(mac_cipher.encrypt(mac_digest1), header_ciphertext)

        # (2-3) framing()과 동일하게, 이제 이 바이트를 ingress_mac에 update
        self.ingress_mac.update(header_mac_seed)

        # (2-4) update된 상태에서 digest() → computed_header_mac
        computed_header_mac = self.ingress_mac.digest()[:16]
        if computed_header_mac != header_mac:
            raise ValueError("Header MAC verification failed")


        # === 3. frame_mac 검증 ===
        # (3-1) framing()과 똑같이, header_mac_seed 이후에 frame_ciphertext를 업데이트
        self.ingress_mac.update(frame_ciphertext)
        mac_digest2 = self.ingress_mac.digest()[:16]

        # (3-2) framing()과 동일하게 frame_mac_seed 계산
        frame_mac_seed = xor_bytes(mac_cipher.encrypt(mac_digest2), mac_digest2)

        # (3-3) framing()과 동일하게 frame_mac_seed를 다시 update
        self.ingress_mac.update(frame_mac_seed)

        # (3-4) 최종 digest() → computed_frame_mac
        computed_frame_mac = self.ingress_mac.digest()[:16]
        if computed_frame_mac != frame_mac:
            raise ValueError("Frame MAC verification failed")

        # === 4. 복호화 ===
        frame_plaintext = aes_frame_cipher.decrypt(frame_ciphertext)

        header_plaintext = aes_header_cipher.decrypt(header_ciphertext)
        # 4-3) header_plaintext의 상위 3바이트를 frame_size로 해석
        #      (원본 데이터의 길이는 framing()에서 len(frame_data).to_bytes(3,'big')로 저장됨)
        frame_size = int.from_bytes(header_plaintext[:3], 'big')
        # 4-4) 패딩 포함 프레임 평문(frame_plaintext)에서 정확히 frame_size만큼만 원본
        frame_data = frame_plaintext[:frame_size]
        return frame_data

    