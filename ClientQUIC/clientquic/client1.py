import asyncio
import ssl

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from RLPx_layer import RLPx_Layer
from config.ECDSA_KEY import STATIC_PRIVATE, STATIC_PUBLIC
from tx_pool import tx_list_array

private_key = STATIC_PRIVATE[1]
public_key = STATIC_PUBLIC[1]
known_peers = [
    ("127.0.0.1", 30300, STATIC_PUBLIC[0]),
]
class ExecutionClientTransport(QuicConnectionProtocol):
    def __init__(self, *args, host, port, private_key, public_key, known_peers, **kwargs):
        super().__init__(*args, **kwargs)
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = known_peers
        self.rlpx_layer = RLPx_Layer(self._quic)

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == 0:
                self.rlpx_layer.set_RLPx_session_initiator2(self.private_key, event.data)
                self.rlpx_layer.handshake_initiator()
            elif event.stream_id == 1:
                msg = self.rlpx_layer.ready_to_receive(event.data)
                print(msg)
                if msg != b'HELLO': raise Exception
                with open("tx_sent.bin", "wb") as f:
                    f.write(self.rlpx_layer.encode_rlp(tx_list_array))
                frame = self.rlpx_layer.ready_to_send(tx_list_array)
                print(len(frame))
                self._quic.send_stream_data(8, frame)


                
async def run():
    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE

    async with connect(
        "127.0.0.1", 
        30300, 
        configuration=config, 
        create_protocol=lambda *args, **kwargs: ExecutionClientTransport(
            *args,
            host="0.0.0.0",
            port=30301,
            private_key=private_key,
            public_key=public_key,
            known_peers=known_peers,
            **kwargs
        )) as execution_client_transport:
        execution_client_transport.rlpx_layer.set_RLPx_session_initiator1(private_key, known_peers[0])
        await asyncio.Future()



if __name__ == "__main__":
    asyncio.run(run())