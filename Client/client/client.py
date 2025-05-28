import asyncio
from RLPx_handshake import handshake_initiator, handshake_receiver
from coincurve import PrivateKey, PublicKey
class Node:
    def __init__(self, host: str, port: int, static_pub: str, static_priv: PrivateKey, peers: list[tuple[str, int]]):
        self.host = host
        self.port = port
        self.static_pub = static_pub
        self.static_priv = static_priv
        # peers: list of (host, port) tuples to connect to
        self.peers = peers
        # active writer streams for broadcasting
        self.connections: list[asyncio.StreamWriter] = []
        # determine outbound peers (only connect to peers with address > self)
        self_address = (self.host, self.port)
        self.outbound_peers = [peer for peer in self.peers if peer < self_address]

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(f"[+] Connection established: {addr}")
        self.connections.append(writer)
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                msg = data.decode().rstrip()
                print(f"[{addr}] {msg}")
        except asyncio.CancelledError:
            pass
        finally:
            print(f"[-] Disconnected: {addr}")
            self.connections.remove(writer)
            writer.close()
            await writer.wait_closed()

    async def start_listener(self):
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        print(f"▶ Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def start_listener(self):
        async def _on_conn(reader, writer):
            addr = writer.get_extra_info('peername')
            print(f"[+] Incoming from {addr}")

            # peers 리스트는 (host, port, static_pub_bytes) 형태여야 합니다.
            aes_sec, mac_sec = await handshake_receiver(
                self.static_priv,
                self.peers,
                reader, writer,
            )
            print(f"[Receiver keys] AES={aes_sec.hex()} MAC={mac_sec.hex()}")

            # TODO: 이 시점에 RLPxConnection 객체에 aes_sec, mac_sec 세팅

        server = await asyncio.start_server(_on_conn, self.host, self.port)
        async with server:
            await server.serve_forever()

    async def connect_to_peer(self, peer):
        while True:
            try:
                reader, writer = await asyncio.open_connection(peer[0], peer[1])
                print(f"[+] Connected to peer {peer[0]}:{peer[1]}")
                aes_sec, mac_sec = await handshake_initiator(self.static_priv, peer[2], reader, writer)
                print(f"[Receiver keys] AES={aes_sec.hex()} MAC={mac_sec.hex()}")
                break
            except Exception as e:
                print(f"[!] Failed to connect to {host}:{port}: {e}. Retrying in 5s...")
                await asyncio.sleep(5)


    async def connect_to_peers(self):
        # only initiate connections to outbound_peers to avoid duplicates
        tasks = [asyncio.create_task(self.connect_to_peer(peer)) for peer in self.outbound_peers]
        await asyncio.gather(*tasks)

    async def broadcast_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            msg = await loop.run_in_executor(None, input, "")
            if not msg:
                continue
            data = (msg + "\n").encode()
            for writer in list(self.connections):
                writer.write(data)
                try:
                    await writer.drain()
                except Exception:
                    pass

    async def run(self):
        # run listener, peer connections, and broadcast tasks concurrently
        await asyncio.gather(
            self.start_listener(),
            self.connect_to_peers(),
            self.broadcast_loop(),
        )

STATIC_PRIV1 = PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d'))
STATIC_PRIV2 = PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')) 
STATIC_PRIV3 = PrivateKey(bytes.fromhex('7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d88428e')) 

if __name__ == "__main__":
    # Define all node addresses
    KNOWN_NODES = [
        ("127.0.0.1", 30300, STATIC_PRIV1.public_key.format(compressed=False), STATIC_PRIV1),
        ("127.0.0.1", 30301, STATIC_PRIV2.public_key.format(compressed=False), STATIC_PRIV2),
        ("127.0.0.1", 30302, STATIC_PRIV3.public_key.format(compressed=False), STATIC_PRIV3),
    ]
    idx = int(input("▶ Enter node index (0, 1, 2): "))
    host, port, static_pub, static_priv = KNOWN_NODES[idx]
    # Exclude self from peer list
    peers = [addr[:3] for i, addr in enumerate(KNOWN_NODES) if i != idx]

    node = Node(host, port, static_pub, static_priv, peers)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("Shutting down...")
