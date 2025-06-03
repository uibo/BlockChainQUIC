import asyncio

from coincurve import PrivateKey, PublicKey
from ecies import decrypt, encrypt
from eth_utils import keccak
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted
from RLPx_layer import RLPx_layer

STATIC_PRIV = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
]

STATIC_PUBL = [
    STATIC_PRIV[0].public_key.format(compressed=False),
    STATIC_PRIV[1].public_key.format(compressed=False),
]


class ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rlpx_layer = RLPx_layer(0, 1)

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == 0:
                enc_ack = self.rlpx_layer.handshake_receiver(event.data)
                self._quic.send_stream_data(event.stream_id, enc_ack)
                print(self.rlpx_layer.aes_sec, self.rlpx_layer.mac_sec)
            

async def main():
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain("ssl_cert.pem", "ssl_key.pem")
    await serve(host="0.0.0.0", port=30300, configuration=config, create_protocol=ServerProtocol)
    print("QUIC 서버가 0.0.0.0:30300에서 대기 중...")
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())