import asyncio

from coincurve import PrivateKey

from RLPx_layer import RLPx_Layer
from config.config import client0

class ExecutionClientTransport:
    def __init__(self, host: str, port: int, private_key: PrivateKey, public_key: bytes, known_peers: list[tuple], expected_streams):
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers

        self.expected_streams = expected_streams
        self.conn_count = 0
        self.connected_event = asyncio.Event()
        self.received_chunk = 0
        self.lock = asyncio.Lock()  # for thread-safe update

    async def on_conn(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[+] Incoming from {addr}")
        rlpx_layer = RLPx_Layer()
        await rlpx_layer.handshake_recepient(self.private_key, known_peers, reader, writer)

        async with self.lock:
            self.conn_count += 1
            print(f"multi-connection complete ({self.conn_count}/{self.expected_streams})")
            if self.conn_count == self.expected_streams:
                self.connected_event.set()
        await self.connected_event.wait()

        msg = await rlpx_layer.receive_frame(reader)
        print(f"got {len(msg)} bytes through any stream")

        self.received_chunk += 1
        if self.received_chunk == 4:
            # 모든 expected stream_id를 다 받았으면 정렬 후 finish
            fin = rlpx_layer.ready_to_send("FIN")
            writer.write(fin)
            writer.write_eof()
            await writer.drain()
            print(f"each stream got {len(rlpx_layer.encode_rlp(msg))}bytes")
    

    async def start_listener(self):
        server = await asyncio.start_server(self.on_conn, self.host, self.port)
        async with server:
            print(f"server listening on {self.host}:{self.port}")
            await server.serve_forever()

    async def run(self):
        await asyncio.gather(
            self.start_listener(),
        )


if __name__ == "__main__":
    private_key = client0["private_key"]
    host, port, public_key = (client0["host"], client0["port"], client0["public_key"])
    known_peers = client0["known_peers"]
    execution_client_transport = ExecutionClientTransport(host, port, private_key, public_key, known_peers, 4)
    asyncio.run(execution_client_transport.run())

