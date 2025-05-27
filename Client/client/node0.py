import asyncio
import config.nodes
from module.enode_socket import start_receiver_server


async def main():
    # 1) 서버 띄우기
    node_num = int(input("Enter Node Num: "))
    enode = config.nodes.set_itself_enode(node_num)
    config.nodes.convert_url_to_enode()
    asyncio.create_task(start_receiver_server(enode))

    # 2) (원한다면) 다른 피어에도 다이얼
    # peers = [{"ip": "...", "port": 30303}, ...]
    # for p in peers:
    #     await connect_to_peer(static_priv, p)

    # 3) 프로그램 종료 방지
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())