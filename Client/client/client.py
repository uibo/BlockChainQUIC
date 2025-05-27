import asyncio

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connections: list[asyncio.StreamWriter] = []

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(f"[+] Connected: {addr}")
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
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"▶ Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def broadcast_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            # 터미널에서 메시지 입력
            msg = await loop.run_in_executor(None, input, "")
            if not msg:
                continue
            data = (msg + "\n").encode()
            # 모든 연결에 브로드캐스트
            for writer in list(self.connections):
                writer.write(data)
                try:
                    await writer.drain()
                except Exception:
                    # 드물지만 연결 끊김 처리
                    pass

    async def run(self):
        # 리스닝과 브로드캐스트를 동시에 실행
        await asyncio.gather(
            self.start_listener(),
            self.broadcast_loop(),
        )

if __name__ == "__main__":
    host = "127.0.0.1"
    port = int(input("▶ 사용할 포트 입력: "))
    node = Node(host, port)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print("Shutting down...")
