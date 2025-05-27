import asyncio
import config.nodes
from module.enode_socket import connect_to_peer

async def main():
    node_num = int(input("Enter Node Num: "))
    enode = config.nodes.set_itself_enode(node_num)
    config.nodes.convert_url_to_enode()

    peer = config.nodes.NODE_STATE.KNOWN_NODES[0]
    conn = await connect_to_peer(enode["static_priv"], peer)

    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())