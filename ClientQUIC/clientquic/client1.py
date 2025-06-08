import asyncio
import time
import ssl

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from RLPx_layer import RLPx_Layer
from config.config import client1
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
        self.start_time = None

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == 0:
                self.rlpx_layer.set_RLPx_session_initiator2(self.private_key, event.data)
                self.rlpx_layer.handshake_initiator()
            elif event.stream_id == 1:
                msg = self.rlpx_layer.ready_to_receive(event.data)
                if msg != b'HELLO': 
                    raise Exception
                else: 
                    print(f"end handshake: {time.time()}")
                self.start_time = time.time()
                frame = self.rlpx_layer.ready_to_send(tx_list_array)
                self._quic.send_stream_data(8, frame)
            else:
                end_time = time.time()
                print(f"RTT TIME: {end_time - self.start_time}")


                
async def run():
    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE

    async with connect(
        host=client1["known_peers"][0][0],
        port=client1["known_peers"][0][1],
        configuration=config, 
        create_protocol=lambda *args, **kwargs: ExecutionClientTransport(
            *args,
            host=client1["host"],
            port=client1["port"],
            private_key=client1["private_key"],
            public_key=client1["public_key"],
            known_peers=client1["known_peers"],
            **kwargs
        )) as execution_client_transport:
        execution_client_transport.rlpx_layer.set_RLPx_session_initiator1(execution_client_transport.private_key, execution_client_transport.known_peers[0])
        await asyncio.Future()



if __name__ == "__main__":
    asyncio.run(run())