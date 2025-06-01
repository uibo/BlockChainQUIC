import asyncio
from RLPx_handshake import handshake_initiator, handshake_receiver
from coincurve import PrivateKey
from Crypto.Cipher import AES
from Crypto.Util import Counter
from eth_utils import keccak
import rlp
from tx_pool import make_tx_list

# define maximum frame size (~2 MiB)
CHUNK_SIZE = 2 * 1024 * 1024
tx_list_array = []

# --- RLPx Connection with Framing & Chunked Send ---
class RLPxConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, aes_secret: bytes, mac_secret: bytes):
        self.reader = reader
        self.writer = writer
        self.aes_secret = aes_secret
        self.mac_secret = mac_secret
        self.egress_seq = 0
        self.ingress_seq = 0

    async def send(self, payload: bytes):
        # single-frame send (header+payload)
        header = len(payload).to_bytes(4, 'big')
        ctr = Counter.new(128, initial_value=self.egress_seq)
        cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=ctr)
        header_enc = cipher.encrypt(header)
        body_enc = cipher.encrypt(payload)
        header_mac = keccak(self.mac_secret + header_enc)[:16]
        body_mac = keccak(self.mac_secret + header_enc + body_enc)[:16]
        self.writer.write(header_enc + header_mac + body_enc + body_mac)
        await self.writer.drain()
        self.egress_seq += 1

    async def send_large(self, data: bytes):
        # split data into CHUNK_SIZE frames
        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i:i+CHUNK_SIZE]
            await self.send(chunk)

    async def receive_loop(self):
        buffer = bytearray()
        try:
            while True:
                # header frame
                header_enc = await self.reader.readexactly(4)
                header_mac = await self.reader.readexactly(16)
                if header_mac != keccak(self.mac_secret + header_enc)[:16]:
                    raise Exception("Header MAC mismatch")
                ctr = Counter.new(128, initial_value=self.ingress_seq)
                cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=ctr)
                header = cipher.decrypt(header_enc)
                length = int.from_bytes(header, 'big')
                # body frame
                body_enc = await self.reader.readexactly(length)
                body_mac = await self.reader.readexactly(16)
                if body_mac != keccak(self.mac_secret + header_enc + body_enc)[:16]:
                    raise Exception("Body MAC mismatch")
                payload_fragment = cipher.decrypt(body_enc)
                buffer.extend(payload_fragment)
                self.ingress_seq += 1
                # if fragment smaller than chunk or buffer complete, try decode
                if len(payload_fragment) < CHUNK_SIZE:
                    try:
                        decoded = rlp.decode(bytes(buffer))
                        print(f"[Decoded {len(decoded)} transactions]")
                    except Exception:
                        print(f"[!] Failed to decode full payload, received {len(buffer)} bytes")
                    buffer.clear()
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[!] Frame error: {e}")
        finally:
            self.writer.close()
            await self.writer.wait_closed()

# --- Node Definition & Initial Broadcast ---
class Node:
    def __init__(self, host: str, port: int, static_pub: bytes, static_priv: PrivateKey, peers: list[tuple]):
        self.host = host
        self.port = port
        self.static_pub = static_pub
        self.static_priv = static_priv
        self.peers = peers
        self.connections: list[RLPxConnection] = []
        self_address = (host, port)
        self.outbound_peers = [p for p in peers if (p[0], p[1]) < self_address]

    async def start_listener(self):
        async def on_conn(reader, writer):
            addr = writer.get_extra_info('peername')
            print(f"[+] Incoming from {addr}")
            aes_sec, mac_sec = await handshake_receiver(self.static_priv, self.peers, reader, writer)
            conn = RLPxConnection(reader, writer, aes_sec, mac_sec)
            self.connections.append(conn)
            asyncio.create_task(conn.receive_loop())
        server = await asyncio.start_server(on_conn, self.host, self.port)
        async with server:
            await server.serve_forever()

    async def connect_to_peer(self, peer):
        host, port, peer_pub = peer
        while True: #연결 돼서 receive_loop호출할때까지 반복복
            try:
                reader, writer = await asyncio.open_connection(host, port)
                aes_sec, mac_sec = await handshake_initiator(self.static_priv, peer_pub, reader, writer)
                conn = RLPxConnection(reader, writer, aes_sec, mac_sec)
                self.connections.append(conn)
                asyncio.create_task(conn.receive_loop())
                break
            except Exception:
                await asyncio.sleep(5)

    async def connect_to_peers(self):
        await asyncio.gather(*(self.connect_to_peer(p) for p in self.outbound_peers))

    async def broadcast_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            msg = await loop.run_in_executor(None, input, "")
            if msg:
                data = (msg + "\n").encode()
                for conn in list(self.connections):
                    await conn.send(data)
    async def initial_tx_broadcast(self):
        # 1) 최소 한 개 이상의 피어 연결 대기
        while not self.connections:
            await asyncio.sleep(0.1)

        # 2) tx_list_array에 들어있는 모든 리스트를 순차 전송
        #    (pop하든 for-in 하든 무방)
        for tx_list in tx_list_array:                
            # RLP로 인코딩해서 bytes 준비
            payload = rlp.encode(tx_list)            

            # 모든 연결에 send_large 호출
            for conn in list(self.connections):
                await conn.send_large(payload)             

        # 3) 보냈다면 원한다면 빈 리스트 처리
        tx_list_array.clear()
        print(f"[+] Sent {len(self.connections)} peers × {len(tx_list_array)} tx-lists")

    async def run(self):
        await asyncio.gather(
            self.start_listener(),
            self.connect_to_peers(),
            self.broadcast_loop(),
            self.initial_tx_broadcast(),
        )

# --- Static Keys & Startup ---
STATIC_PRIV = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d88428e')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884282')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884283')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884284')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884285')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884286')),
    PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884287')),
]


if __name__ == "__main__":
    for _ in range(100):
        tx_list_array.append(make_tx_list(200)) 
    static_priv = STATIC_PRIV[0]
    host, port, static_pub = ("0.0.0.0", 30300, static_priv.public_key.format(compressed=False))
    KNOWN_NODES = [
        ("127.0.0.1", 30300, STATIC_PRIV[0].public_key.format(compressed=False)),
        ("127.0.0.1", 30301, STATIC_PRIV[1].public_key.format(compressed=False)),
        ("127.0.0.1", 30302, STATIC_PRIV[2].public_key.format(compressed=False)),
        ("127.0.0.1", 30303, STATIC_PRIV[3].public_key.format(compressed=False)),
        ("127.0.0.1", 30304, STATIC_PRIV[4].public_key.format(compressed=False)),
        ("127.0.0.1", 30305, STATIC_PRIV[5].public_key.format(compressed=False)),
        ("127.0.0.1", 30306, STATIC_PRIV[6].public_key.format(compressed=False)),
        ("127.0.0.1", 30307, STATIC_PRIV[7].public_key.format(compressed=False)),
        ("127.0.0.1", 30308, STATIC_PRIV[8].public_key.format(compressed=False)),
    ]
    idx = int(input("▶ Enter node index (0, 1, 2): "))
    host, port, static_pub = KNOWN_NODES[idx]
    static_priv = STATIC_PRIV[idx]
    peers = [n for i, n in enumerate(KNOWN_NODES) if i != idx]

    node = Node(host, port, static_pub, static_priv, peers)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("Shutting down...")
