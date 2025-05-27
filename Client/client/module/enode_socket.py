import asyncio
import socket
from coincurve import PrivateKey
from module.RLPx_layer import make_shared_secret_by_initiator, make_shared_secret_by_receiver

class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 aes_key: bytes, mac_key: bytes, peer_id: str):
        self.reader = reader
        self.writer = writer
        self.aes = aes_key
        self.mac = mac_key
        self.peer_id = peer_id

    async def recv_loop(self):
        try:
            while True:
                data = await self.reader.read(4096)
                if not data:
                    print(f"[{self.peer_id}] disconnected")
                    break
                # TODO: decrypt & verify MAC if 필요
                print(f"[{self.peer_id}] ▶ {data.decode()}")
        finally:
            self.writer.close()
            await self.writer.wait_closed()

class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, Connection] = {}

    async def add(self, conn: Connection):
        self.connections[conn.peer_id] = conn
        # 수신·송신 루프 백그라운드 실행
        asyncio.create_task(conn.recv_loop())

    async def broadcast_loop(self):
            """전체 커넥션에 메시지를 보내는 공통 송신 루프"""
            loop = asyncio.get_running_loop()
            while True:
                # input()을 별도 스레드에서 논블로킹으로 대기
                msg = await loop.run_in_executor(None, input, "Broadcast >> ")
                if not msg:
                    continue

                # 등록된 모든 커넥션에 전송
                dead = []
                for peer_id, conn in self.connections.items():
                    try:
                        # TODO: 암호화 & MAC 추가
                        conn.writer.write(msg.encode())
                        await conn.writer.drain()
                    except Exception as e:
                        print(f"[{peer_id}] send error: {e}")
                        dead.append(peer_id)

                # 연결 끊긴 피어 정리
                for pid in dead:
                    self.connections.pop(pid, None)
                    print(f"[{pid}] removed from manager")

manager = ConnectionManager()

async def start_receiver_server(enode: dict):
    server = await asyncio.start_server(
        client_connected_cb,
        host=enode["ip"],
        port=enode["port"],
    )
    async with server:
        await server.serve_forever()

async def client_connected_cb(reader, writer):
    aes, mac = await make_shared_secret_by_receiver(reader, writer)
    peer = writer.get_extra_info('peername')
    peer_id = f"{peer[0]}:{peer[1]}"
    print(f"▶ Handshake with {peer_id}: aes={aes.hex()}, mac={mac.hex()}")

    conn = Connection(reader, writer, aes, mac, peer_id)
    await manager.add(conn)

async def connect_to_peer(static_priv: bytes, peer: dict):
    reader, writer = await asyncio.open_connection(
        host=peer["ip"],
        port=peer["port"]
    )
    aes, mac = await make_shared_secret_by_initiator(
        PrivateKey(static_priv), reader, writer
    )
    peer_id = f"{peer['ip']}:{peer['port']}"
    print(f"▶ Handshake with {peer_id}: aes={aes.hex()}, mac={mac.hex()}")

    conn = Connection(reader, writer, aes, mac, peer_id)
    await manager.add(conn)
    return conn