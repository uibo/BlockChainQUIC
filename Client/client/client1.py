import asyncio
import time

from coincurve import PrivateKey

from RLPx_layer import RLPx_Layer
from config.config import client1
from config.tx_pool import tx_list_array

class ExecutionClientTransport:
    def __init__(self, host: str, port: int, private_key: PrivateKey, public_key: bytes, known_peers: list[tuple]):
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers
        self.rlpx_layer = RLPx_Layer()
     
    async def connect_to_peer(self, peer: tuple[str, int, bytes]):
        reader, writer = await asyncio.open_connection(peer[0], peer[1])
        await self.rlpx_layer.handshake_initiator(self.private_key, known_peers[0], reader, writer)
        with open("tx_sent.bin", "wb") as f:
            f.write(self.rlpx_layer.encode_rlp(tx_list_array))
        start_time = time.perf_counter()
        print(f"sending_time: {start_time}")
        frame = self.rlpx_layer.ready_to_send(tx_list_array)
        writer.write(frame)
        await writer.drain()


    async def run(self):
        await asyncio.gather(
            self.connect_to_peer(self.known_peers[0]),
        )


if __name__ == "__main__":
    private_key = client1["private_key"]
    host, port, public_key = (client1["host"], client1["port"], client1["public_key"])
    known_peers = client1["known_peers"]
    execution_client_transport = ExecutionClientTransport(host, port, private_key, public_key, known_peers)
    asyncio.run(execution_client_transport.run())

