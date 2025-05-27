# RLPx_layer.py 맨 아래에 추가

# from Crypto.Cipher import AES
# from Crypto.Hash import keccak
# from Crypto.Util import Counter

# class RLPxCipher:
#     def __init__(self, aes_secret: bytes, mac_secret: bytes, init_nonce: bytes):
#         # ── 1) AES-CTR 스트림 객체 준비 (기밀성)
#         ctr_enc = Counter.new(128, initial_value=0)
#         ctr_dec = Counter.new(128, initial_value=0)
#         self._enc_cipher = AES.new(aes_secret, AES.MODE_CTR, counter=ctr_enc)
#         self._dec_cipher = AES.new(aes_secret, AES.MODE_CTR, counter=ctr_dec)

#         # ── 2) MAC 상태 초기화 (무결성)
#         # init_mac = keccak256(mac_secret XOR init_nonce)
#         initial = bytes(a ^ b for a, b in zip(mac_secret, init_nonce))
#         self._egress_mac = keccak.new(digest_bits=256)
#         self._egress_mac.update(initial)
#         self._ingress_mac = keccak.new(digest_bits=256)
#         self._ingress_mac.update(initial)

#         self._mac_secret = mac_secret

#     def encrypt_frame(self, payload: bytes) -> bytes:
#         # ——————————————————————————————
#         # A) 헤더 생성 & 암호화
#         header = len(payload).to_bytes(4, 'big')                # (1) 4바이트 길이
#         header_ct = self._enc_cipher.encrypt(header)           # (2) AES-CTR

#         # B) 헤더 MAC 계산
#         seed_h = AES.new(self._mac_secret, AES.MODE_ECB)       \
#                    .encrypt(self._egress_mac.digest()[:16])   # (3) 중간 시드 생성
#         header_mac_seed = bytes(a ^ b for a, b in zip(seed_h, header_ct))
#         self._egress_mac.update(header_mac_seed)               # (4) MAC 상태 갱신
#         header_mac = self._egress_mac.digest()[:16]            # (5) 헤더 MAC

#         # C) 프레임(페이로드) 암호화
#         frame_ct = self._enc_cipher.encrypt(payload)           # (6) AES-CTR

#         # D) 프레임 MAC 계산
#         self._egress_mac.update(frame_ct)                      # (7) MAC 상태 갱신
#         seed_f = AES.new(self._mac_secret, AES.MODE_ECB)       \
#                    .encrypt(self._egress_mac.digest()[:16])   # (8) 중간 시드
#         frame_mac_seed = bytes(a ^ b for a, b in zip(seed_f,
#                                                      self._egress_mac.digest()[:16]))
#         self._egress_mac.update(frame_mac_seed)                # (9) MAC 상태 갱신
#         frame_mac = self._egress_mac.digest()[:16]             # (10) 프레임 MAC

#         # E) 최종 프레임 구조: header_ct ∥ header_mac ∥ frame_ct ∥ frame_mac
#         return header_ct + header_mac + frame_ct + frame_mac

#     def decrypt_frame(self, data: bytes) -> bytes:
#         # ——————————————————————————————
#         # A) 슬라이스
#         header_ct   = data[0:4]
#         header_mac  = data[4:20]
#         frame_mac   = data[-16:]
#         frame_ct    = data[20:-16]

#         # B) 헤더 MAC 검증
#         seed_h = AES.new(self._mac_secret, AES.MODE_ECB)       \
#                    .encrypt(self._ingress_mac.digest()[:16])  # (1) 중간 시드
#         header_mac_seed = bytes(a ^ b for a, b in zip(seed_h, header_ct))
#         self._ingress_mac.update(header_mac_seed)              # (2) MAC 상태 갱신
#         if header_mac != self._ingress_mac.digest()[:16]:      # (3) MAC 비교
#             raise ValueError("Header MAC mismatch")

#         # C) 헤더 복호화 → payload 길이
#         header = self._dec_cipher.encrypt(header_ct)           # CTR decryption == encrypt
#         length = int.from_bytes(header, 'big')

#         # D) 프레임 MAC 검증
#         self._ingress_mac.update(frame_ct)                     # (4) MAC 상태 갱신
#         seed_f = AES.new(self._mac_secret, AES.MODE_ECB)       \
#                    .encrypt(self._ingress_mac.digest()[:16])  # (5) 중간 시드
#         frame_mac_seed = bytes(a ^ b for a, b in zip(seed_f,
#                                                      self._ingress_mac.digest()[:16]))
#         self._ingress_mac.update(frame_mac_seed)               # (6) MAC 상태 갱신
#         if frame_mac != self._ingress_mac.digest()[:16]:       # (7) MAC 비교
#             raise ValueError("Frame MAC mismatch")

#         # E) 페이로드 복호화 & 리턴
#         payload = self._dec_cipher.encrypt(frame_ct)           # CTR decryption == encrypt
#         return payload[:length]