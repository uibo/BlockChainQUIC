import asyncio

class Node:
    def __init__(self, host: str, port: int, peers: list[tuple[str, int]]):
        self.host = host
        self.port = port
        # peers: list of (host, port) tuples to connect to
        self.peers = peers
        # active writer streams for broadcasting
        self.connections: list[asyncio.StreamWriter] = []
        # determine outbound peers (only connect to peers with address > self)
        self_address = (self.host, self.port)
        self.outbound_peers = [peer for peer in self.peers if peer > self_address]

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

    async def connect_to_peer(self, host: str, port: int):
        while True:
            try:
                reader, writer = await asyncio.open_connection(host, port)
                print(f"[+] Connected to peer {host}:{port}")
                # handle incoming messages from this peer
                asyncio.create_task(self.handle_connection(reader, writer))
                break
            except Exception as e:
                print(f"[!] Failed to connect to {host}:{port}: {e}. Retrying in 5s...")
                await asyncio.sleep(5)

    async def connect_to_peers(self):
        # only initiate connections to outbound_peers to avoid duplicates
        tasks = [asyncio.create_task(self.connect_to_peer(h, p)) for h, p in self.outbound_peers]
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


if __name__ == "__main__":
    # Define all node addresses
    KNOWN_NODES = [
        ("127.0.0.1", 30300),
        ("127.0.0.1", 30301),
        ("127.0.0.1", 30302),
    ]
    idx = int(input("▶ Enter node index (0, 1, 2): "))
    host, port = KNOWN_NODES[idx]
    # Exclude self from peer list
    peers = [addr for i, addr in enumerate(KNOWN_NODES) if i != idx]

    node = Node(host, port, peers)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("Shutting down...")
