import asyncio
import config.nodes
from module.enode_socket import start_receiver_server, connect_to_peer, manager

async def main():
    node_num = int(input("Enter Node Num: "))
    enode = config.nodes.set_itself_enode(node_num)
    config.nodes.convert_url_to_enode()

    # 1) 서버(리스닝) 시작
    server_task = asyncio.create_task(start_receiver_server(enode))
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, input, "Press Enter once all servers are up…")
    # 2) 남은 피어 전부 다이얼
    for peer in config.nodes.NODE_STATE.KNOWN_NODES:
        await connect_to_peer(enode["static_priv"], peer)


    asyncio.create_task(manager.broadcast_loop())
    # 3) 프로그램을 종료하지 않도록 대기
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())