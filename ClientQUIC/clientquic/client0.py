import asyncio
import time

from Crypto.Cipher import AES
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from Crypto.Util import Counter

from RLPx_layer import RLPx_Layer
from config.config import client0
from config.tx_pool import tx_list_array

class ExecutionClientTransport(QuicConnectionProtocol):
    def __init__(self, *args, host, port, private_key, public_key, known_peers, **kwargs):
        super().__init__(*args, **kwargs)
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers
        self.rlpx_layer = RLPx_Layer(self._quic)

        self._stream_queues: dict[int, asyncio.Queue[bytes]] = {}
        self._stream_handlers: dict[int, asyncio.Task] = {}
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._stream_queues[8] = queue
        self._stream_handlers[8] = asyncio.create_task(self.handle_stream(8, self._stream_queues[8]))

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if stream_id == 8:
                self._stream_queues[8].put_nowait(data)

            if stream_id == 0:
                self.rlpx_layer.set_RLPx_session_recipient(self.private_key, self.known_peers, event.data)
                self.rlpx_layer.handshake_recepient()
            elif stream_id == 4:
                msg = self.rlpx_layer.ready_to_receive(event.data)
                if msg != b'HELLO': raise Exception
                else: print(f"end handshake: {time.time()}")

    async def handle_stream(self, stream_id: int, queue: asyncio.Queue[bytes]) -> None:
        buffer = bytearray()
        chunk = await queue.get()
        buffer.extend(chunk)
        self.aes_secret = self.rlpx_layer.aes_secret
        aes_header_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
        header_ciphertext = buffer[:16]
        header_plaintext = aes_header_cipher.decrypt(header_ciphertext)
        frame_size = int.from_bytes(header_plaintext[:3], 'big')
        ciphertext_len = ((frame_size + 15) // 16) * 16
        full_frame_size = 16 + 16 + ciphertext_len + 16
        while True:
            chunk = await queue.get()
            buffer.extend(chunk)
            if len(buffer) >= full_frame_size:
                full_frame = bytes(buffer[:full_frame_size])
                del buffer[:full_frame_size]
                if stream_id == 8:
                    msg = self.rlpx_layer.ready_to_receive(full_frame)
                    print(f"receiving time: {time.time()}")
                    recv = self.rlpx_layer.encode_rlp(msg)
                    sent = self.rlpx_layer.encode_rlp(tx_list_array)

                    if sent == recv:
                        print("✅ 보내고 받은 페이로드가 완전히 일치합니다.")
                    else:
                        print("❌ 페이로드가 다릅니다.")

async def main():
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain("ssl_cert.pem", "ssl_key.pem")
    await serve(host=client0["host"], 
                port=client0["port"], 
                configuration=config, 
                create_protocol=lambda *args, **kwargs: ExecutionClientTransport(
            *args,
            host=client0["host"],
            port=client0["port"],
            private_key=client0["private_key"],
            public_key=client0["public_key"],
            known_peers=client0["known_peers"],
            **kwargs
        ))
    print("QUIC 서버가 0.0.0.0:30300에서 대기 중...")
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())