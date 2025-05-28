import struct
from Crypto.Cipher import AES
from eth_utils import keccak

class RLPxFramer:
    def __init__(self, aes_secret: bytes, mac_secret: bytes,
                 initiator_nonce: bytes, recipient_nonce: bytes, is_initiator: bool):
        # AES-CTR 스트림 (IV은 0)
        self.enc_cipher = AES.new(aes_secret, AES.MODE_CTR, nonce=b"", initial_value=0)
        self.dec_cipher = AES.new(aes_secret, AES.MODE_CTR, nonce=b"", initial_value=0)
        self.mac_secret = mac_secret

        # MAC 상태 초기화
        self.egress_mac = keccak()
        self.ingress_mac = keccak()
        if is_initiator:
            self.egress_mac.update(bytes(a ^ b for a, b in zip(mac_secret, recipient_nonce)))
            self.egress_mac.update(initiator_nonce)
            self.ingress_mac.update(bytes(a ^ b for a, b in zip(mac_secret, initiator_nonce)))
            self.ingress_mac.update(recipient_nonce)
        else:
            self.egress_mac.update(bytes(a ^ b for a, b in zip(mac_secret, initiator_nonce)))
            self.egress_mac.update(recipient_nonce)
            self.ingress_mac.update(bytes(a ^ b for a, b in zip(mac_secret, recipient_nonce)))
            self.ingress_mac.update(initiator_nonce)

    def _header_mac(self, header_ciphertext: bytes) -> bytes:
        seed = bytes(a ^ b for a, b in zip(
            AES.new(self.mac_secret, AES.MODE_ECB).encrypt(keccak(self.egress_mac.digest()).digest()[:16]),
            header_ciphertext))
        self.egress_mac.update(seed)
        return keccak(self.egress_mac.digest()).digest()[:16]

    def _frame_mac(self, frame_ciphertext: bytes) -> bytes:
        self.egress_mac.update(frame_ciphertext)
        interim = keccak(self.egress_mac.digest()).digest()[:16]
        seed = bytes(a ^ b for a, b in zip(
            AES.new(self.mac_secret, AES.MODE_ECB).encrypt(interim),
            interim))
        self.egress_mac.update(seed)
        return keccak(self.egress_mac.digest()).digest()[:16]

    def send_frame(self, writer, msg_id: int, msg_data: bytes):
        # 1) frame-data 조립
        payload = bytes([msg_id]) + msg_data
        frame_size = len(payload)
        header = struct.pack(">I", frame_size)[1:]  # 24bit big-endian
        header += b'\x00\x00'  # capability-id, context-id = 0
        header = header.ljust(16, b'\x00')  # 16바이트 정렬
        # 2) 암호화 및 MAC
        header_ct = self.enc_cipher.encrypt(header)
        header_mac = self._header_mac(header_ct)
        frame_ct = self.enc_cipher.encrypt(payload.ljust(
            ((len(payload)+15)//16)*16, b'\x00'))
        frame_mac = self._frame_mac(frame_ct)
        # 3) 전송
        writer.write(header_ct + header_mac + frame_ct + frame_mac)

    async def recv_frame(self, reader):
        # 1) header_ciphertext + header_mac
        header_ct = await reader.readexactly(16)
        header_mac = await reader.readexactly(16)
        # MAC 검증
        expected = self._header_mac(header_ct)
        if expected != header_mac:
            raise Exception("header MAC mismatch")
        header = self.dec_cipher.decrypt(header_ct)
        frame_size = int.from_bytes(header[:3], "big")
        # 2) frame_ciphertext + frame_mac
        frame_ct = await reader.readexactly(((frame_size+15)//16)*16)
        frame_mac = await reader.readexactly(16)
        if self._frame_mac(frame_ct) != frame_mac:
            raise Exception("frame MAC mismatch")
        payload = self.dec_cipher.decrypt(frame_ct)[:frame_size]
        return payload[0], payload[1:]