import re

NODES = [
    ("enode://2a3daa4cab5cddff3c81ad1113e5fa9bdf3c9f5087806cadf0f038c44f7ddfd19672c1ed7de65863897125bd5f9ce88c3efa8fe19cebc5ff274d66e3c31d0fb7@127.0.0.1:30303", 0x48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d),
    ("enode://d6cd9095aba8253ca82c0cd5a8d78a3536adfe31b5ec4555934369a12f960b0461de24d6eee6514583cdaf55dd3aabd7b510c705e9882898f14041a47a8be7e5@127.0.0.1:30304", 0x8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f),
]

def extract_enode_info(enode_url: str):
    # 정규 표현식으로 node_id, ip, port 추출
    match = re.match(r"enode://([0-9a-fA-F]{128})@([\d\.]+):(\d+)", enode_url)
    if match:
        node_id = match.group(1)
        ip = match.group(2)
        port = int(match.group(3))
        return node_id, ip, port
    
def set_itself_enode(num: int):
    node_id, ip, port = extract_enode_info(NODES[num][0])
    static_priv = NODES[num][1]
    NODES.remove(NODES[num])
    return {"node_id": node_id, "ip": ip, "port": port, "static_priv": static_priv}
