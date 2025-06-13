import time
import asyncio

from coincurve import PrivateKey

from RLPx_layer import RLPx_Layer
from config.config import client0

class ExecutionClientTransport:
    def __init__(self, host: str, port: int, private_key: PrivateKey, public_key: bytes, known_peers: list[tuple]):
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers
        self.rlpx_layer = RLPx_Layer()

    async def on_conn(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[+] Incoming from {addr}")
        await self.rlpx_layer.handshake_recepient(self.private_key, known_peers, reader, writer)
        msg = await self.rlpx_layer.receive_frame(reader)
        msg = "fin"
        frame = self.rlpx_layer.ready_to_send(msg)
        writer.write(frame)
        await writer.drain()

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
    execution_client_transport = ExecutionClientTransport(host, port, private_key, public_key, known_peers)
    asyncio.run(execution_client_transport.run())