import asyncio
from RLPx_handshake import handshake_initiator, handshake_receiver
from coincurve import PrivateKey
from Crypto.Cipher import AES
from Crypto.Util import Counter
from eth_utils import keccak
from tx_pool import tx_pool
import rlp
class RLPxConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, aes_secret: bytes, mac_secret: bytes):
        self.reader = reader
        self.writer = writer
        self.aes_secret = aes_secret
        self.mac_secret = mac_secret
        self.egress_seq = 0
        self.ingress_seq = 0

    async def send(self, payload: bytes):
        # 1) Prepare 4-byte header
        header = len(payload).to_bytes(4, 'big')
        # 2) Encrypt header and body with AES-CTR
        ctr = Counter.new(128, initial_value=self.egress_seq)
        cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=ctr)
        header_cipher = cipher.encrypt(header)
        body_cipher = cipher.encrypt(payload)
        # 3) Compute MACs
        header_mac = keccak(self.mac_secret + header_cipher)[:16]
        body_mac = keccak(self.mac_secret + header_cipher + body_cipher)[:16]
        # 4) Send frame: header_cipher || header_mac || body_cipher || body_mac
        self.writer.write(header_cipher + header_mac + body_cipher + body_mac)
        await self.writer.drain()
        self.egress_seq += 1

    async def receive_loop(self):
        try:
            while True:
                # Read encrypted header and MAC
                header_cipher = await self.reader.readexactly(4)
                header_mac = await self.reader.readexactly(16)
                # Verify header MAC
                if header_mac != keccak(self.mac_secret + header_cipher)[:16]:
                    raise Exception("Header MAC mismatch")
                # Decrypt header to get body length
                ctr = Counter.new(128, initial_value=self.ingress_seq)
                cipher = AES.new(self.aes_secret, AES.MODE_CTR, counter=ctr)
                header = cipher.decrypt(header_cipher)
                body_len = int.from_bytes(header, 'big')
                # Read encrypted body and MAC
                body_cipher = await self.reader.readexactly(body_len)
                body_mac = await self.reader.readexactly(16)
                # Verify body MAC
                if body_mac != keccak(self.mac_secret + header_cipher + body_cipher)[:16]:
                    raise Exception("Body MAC mismatch")
                # Decrypt payload
                payload = cipher.decrypt(body_cipher)
                self.ingress_seq += 1
                # Print received message
                addr = self.writer.get_extra_info('peername')
                print(f"[{addr}] {rlp.decode(payload)}")
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[!] Frame error: {e}")
        finally:
            self.writer.close()
            await self.writer.wait_closed()

class Node:
    def __init__(self, host: str, port: int, static_pub: bytes, static_priv: PrivateKey, peers: list[tuple]):
        self.host = host
        self.port = port
        self.static_pub = static_pub
        self.static_priv = static_priv
        # peers: list of (host, port, static_pub_bytes)
        self.peers = peers
        # active RLPxConnection objects
        self.connections: list[RLPxConnection] = []
        # only connect to peers with address less than self to avoid duplicates
        self_address = (self.host, self.port)
        self.outbound_peers = [p for p in self.peers if (p[0], p[1]) < self_address]

    async def start_listener(self):
        async def _on_conn(reader, writer):
            addr = writer.get_extra_info('peername')
            print(f"[+] Incoming from {addr}")
            # perform handshake as receiver
            aes_sec, mac_sec = await handshake_receiver(self.static_priv, self.peers, reader, writer)
            print(f"[Receiver keys] AES={aes_sec.hex()} MAC={mac_sec.hex()}")
            # wrap in RLPxConnection
            conn = RLPxConnection(reader, writer, aes_sec, mac_sec)
            self.connections.append(conn)
            # start receiving frames
            asyncio.create_task(conn.receive_loop())

        server = await asyncio.start_server(_on_conn, self.host, self.port)
        print(f"▶ Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def connect_to_peer(self, peer):
        host, port, peer_pub = peer
        while True:
            try:
                reader, writer = await asyncio.open_connection(host, port)
                print(f"[+] Connected to peer {host}:{port}")
                # perform handshake as initiator
                aes_sec, mac_sec = await handshake_initiator(self.static_priv, peer_pub, reader, writer)
                print(f"[Initiator keys] AES={aes_sec.hex()} MAC={mac_sec.hex()}")
                # wrap in RLPxConnection
                conn = RLPxConnection(reader, writer, aes_sec, mac_sec)
                self.connections.append(conn)
                asyncio.create_task(conn.receive_loop())
                break
            except Exception as e:
                print(f"[!] Failed to connect to {host}:{port}: {e}. Retrying in 5s...")
                await asyncio.sleep(5)

    async def connect_to_peers(self):
        tasks = [asyncio.create_task(self.connect_to_peer(p)) for p in self.outbound_peers]
        await asyncio.gather(*tasks)

    async def broadcast_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            msg = await loop.run_in_executor(None, input, "")
            if not msg:
                continue
            for conn in list(self.connections):
                try:   
                    for tx in tx_pool:
                        await conn.send(tx)
                except Exception:
                    pass

    async def run(self):
        await asyncio.gather(
            self.start_listener(),
            self.connect_to_peers(),
            self.broadcast_loop(),
        )

# static keys for example nodes secp256k1
STATIC_PRIV = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d88428e')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884282')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884283')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884284')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884285')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884286')),
    # PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d884287')),
]

if __name__ == "__main__":
    KNOWN_NODES = [
        ("127.0.0.1", 30300, STATIC_PRIV[0].public_key.format(compressed=False)),
        ("127.0.0.1", 30301, STATIC_PRIV[1].public_key.format(compressed=False)),
        # ("127.0.0.1", 30302, STATIC_PRIV[2].public_key.format(compressed=False)),
        # ("127.0.0.1", 30303, STATIC_PRIV[3].public_key.format(compressed=False)),
        # ("127.0.0.1", 30304, STATIC_PRIV[4].public_key.format(compressed=False)),
        # ("127.0.0.1", 30305, STATIC_PRIV[5].public_key.format(compressed=False)),
        # ("127.0.0.1", 30306, STATIC_PRIV[6].public_key.format(compressed=False)),
        # ("127.0.0.1", 30307, STATIC_PRIV[7].public_key.format(compressed=False)),
        # ("127.0.0.1", 30308, STATIC_PRIV[8].public_key.format(compressed=False)),
    ]
    idx = int(input("▶ Enter node index (0 ~ 8): "))
    host, port, static_pub = KNOWN_NODES[idx]
    static_priv = STATIC_PRIV[idx]
    peers = [node for i, node in enumerate(KNOWN_NODES) if i != idx]

    node = Node(host, port, static_pub, static_priv, peers)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("Shutting down...")
