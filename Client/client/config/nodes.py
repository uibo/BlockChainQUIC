import re

class NodeState:
    def __init__(self):
        self.ENODES = [
            ("enode://042a3daa4cab5cddff3c81ad1113e5fa9bdf3c9f5087806cadf0f038c44f7ddfd19672c1ed7de65863897125bd5f9ce88c3efa8fe19cebc5ff274d66e3c31d0fb7@127.0.0.1:30303", '48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d'),
            ("enode://04d6cd9095aba8253ca82c0cd5a8d78a3536adfe31b5ec4555934369a12f960b0461de24d6eee6514583cdaf55dd3aabd7b510c705e9882898f14041a47a8be7e5@127.0.0.1:30304", '8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f'),
            ("enode://04e91d3b255f955901fafcc186ea250bcfd690b43b83ec4be5afbb10c2dabb1ae12b455d486320d455f1aff7026d95c7d94f9b8d39d8ced4386a35844d66ce9623@127.0.0.1:30305", '7f6321d1445b2c00e23f1dd660908b52974ab12edb237d603e07d08f9d88428e'),
        ]
        self.KNOWN_NODES = []
        self.CONNECTED_NODES = []

NODE_STATE = NodeState()

def extract_enode_info(enode_url: str):
    # 정규 표현식으로 node_id, ip, port 추출
    match = re.match(r"enode://([0-9a-fA-F]{130})@([\d\.]+):(\d+)", enode_url)
    if match:
        node_id = match.group(1)
        ip = match.group(2)
        port = int(match.group(3))
        return node_id, ip, port
    
def set_itself_enode(num: int):
    node_id, ip, port = extract_enode_info(NODE_STATE.ENODES[num][0])
    static_priv = NODE_STATE.ENODES[num][1]
    NODE_STATE.ENODES.remove(NODE_STATE.ENODES[num])
    enode = {"node_id": node_id, "ip": ip, "port": port, "static_priv": bytes.fromhex(static_priv)}
    return enode

def convert_url_to_enode():
    for node in NODE_STATE.ENODES:
        node_id, ip, port = extract_enode_info(node[0])
        NODE_STATE.KNOWN_NODES.append({"node_id": node_id, "ip": ip, "port": port})