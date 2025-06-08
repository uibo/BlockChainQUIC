import asyncio
import time
from coincurve import PrivateKey

from RLPx_layer import RLPx_Layer
from config.config import client1
from config.tx_pool import chunks

class ExecutionClientTransport:
    def __init__(self, host: str, port: int, private_key: PrivateKey, public_key: bytes, known_peers: list[tuple]):
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers

    async def connect_and_send_to_peer(self, peer: tuple[str, int, bytes], chunk):
        reader, writer = await asyncio.open_connection(peer[0], peer[1])
        rlpx_layer = RLPx_Layer()
        await rlpx_layer.handshake_initiator(self.private_key, peer, reader, writer)
        start_time = time.time()
        frame = rlpx_layer.ready_to_send(chunk)
        writer.write(frame)
        await writer.drain()
        msg = await reader.read()
        msg = rlpx_layer.ready_to_receive(msg)
        end_time = time.time()
        print(f"{msg}, RTT TIME: {end_time - start_time:7.4f}")

    async def run(self):

        # 4개의 코루틴을 만들어 병렬 실행
        await asyncio.gather(*[
            self.connect_and_send_to_peer(self.known_peers[0], chunks[i])
            for i in range(4)
        ])


if __name__ == "__main__":
    private_key = client1["private_key"]
    host, port, public_key = (client1["host"], client1["port"], client1["public_key"])
    known_peers = client1["known_peers"]
    execution_client_transport = ExecutionClientTransport(host, port, private_key, public_key, known_peers)
    asyncio.run(execution_client_transport.run())
