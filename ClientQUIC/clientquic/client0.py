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

class ExecutionClientTransport(QuicConnectionProtocol):
    def __init__(self, *args, host, port, private_key, public_key, known_peers, **kwargs):
        super().__init__(*args, **kwargs)
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers
        self.rlpx_layer = RLPx_Layer(self._quic)
        self._receive_lock = asyncio.Lock()
        # Stream-specific queues and handlers
        self._stream_queues: dict[int, asyncio.Queue[bytes]] = {}
        self._stream_handlers: dict[int, asyncio.Task] = {}
        self.stream_order = [12, 16, 20, 24]


    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if stream_id == 0:
                self.rlpx_layer.set_RLPx_session_recipient(self.private_key, self.known_peers, event.data)
                self.rlpx_layer.handshake_recepient()
            elif stream_id == 4:
                msg = self.rlpx_layer.ready_to_receive(event.data)
                if msg != b'HELLO': 
                    raise Exception
                else: 
                    print(f"end handshake: {time.time()}")
            else:
                # For any other stream, create a queue+handler if not exists
                if stream_id not in self._stream_queues:
                    queue: asyncio.Queue[bytes] = asyncio.Queue()
                    self._stream_queues[stream_id] = queue
                    # Launch a handler task for this stream
                    self._stream_handlers[stream_id] = asyncio.create_task(
                        self.handle_stream(stream_id, queue)
                    )
                # Enqueue received data
                self._stream_queues[stream_id].put_nowait(data)

    async def handle_stream(self, stream_id: int, queue: asyncio.Queue[bytes]) -> None:
        buffer = bytearray()
        self.aes_secret = self.rlpx_layer.aes_secret
        aes_header_cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
 
        # Read header 
        chunk = await queue.get()
        buffer.extend(chunk)
        header_ciphertext = buffer[:16]
        header_plaintext = aes_header_cipher.decrypt(header_ciphertext)
        frame_size = int.from_bytes(header_plaintext[:3], 'big')
        ciphertext_len = ((frame_size + 15) // 16) * 16
        full_frame_size = 16 + 16 + ciphertext_len + 16

        # Continue accumulating until full frame is available
        while len(buffer) < full_frame_size:
            chunk = await queue.get()
            buffer.extend(chunk)

        # Extract full frame and process
        full_frame = bytes(buffer[:full_frame_size])
        del buffer[:full_frame_size]
        # 2) 내 차례가 될 때까지 대기
        #    stream_order의 첫 요소가 내 stream_id가 아니면 짧게 슬립
        while True:
            # 락 없이도 순서만 확인
            if self.stream_order and self.stream_order[0] == stream_id:
                break
            await asyncio.sleep(0.005)  # 5ms 정도

        # 3) 이제 MAC 체인 보호 락 안에서 실제 디코딩
        async with self._receive_lock:
            message = self.rlpx_layer.ready_to_receive(full_frame)
            print(f"[stream {stream_id}] receiving time: {time.time()}")

            # 4) 처리 끝났으면 순서 대기열에서 내 ID 제거
            self.stream_order.pop(0)
            if not self.stream_order:
                frame = self.rlpx_layer.ready_to_send(b'FIN')
                self._quic.send_stream_data(self._quic.get_next_available_stream_id(), frame)

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