import asyncio
import ssl

from eth_utils import keccak
from ecies import encrypt, decrypt
from coincurve import PrivateKey
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ProtocolNegotiated, HandshakeCompleted

from RLPx_layer import RLPx_layer

STATIC_PRIV = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
]

STATIC_PUBL = [
    STATIC_PRIV[0].public_key.format(compressed=False),
    STATIC_PRIV[1].public_key.format(compressed=False),
]
    
class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rlpx_layer = RLPx_layer(1, 0)

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            if (event.stream_id == 0):
                self.rlpx_layer.handshake_initiator2(event.data)
                print(self.rlpx_layer.aes_sec, self.rlpx_layer.mac_sec)
       
async def run():
    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE

    async with connect("127.0.0.1", 30300, configuration=config, create_protocol=ClientProtocol) as conn:
        stream_id = conn._quic.get_next_available_stream_id()
        enc_auth = conn.rlpx_layer.handshake_initiator1()
        conn._quic.send_stream_data(stream_id, enc_auth)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(run())