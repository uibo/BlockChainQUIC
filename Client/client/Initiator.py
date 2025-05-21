from module.enode_socket import make_connection_by_accept, make_connection_by_connect
from module.RLPx_layer import make_shared_secret_by_initiator, make_shared_secret_by_receiver
from config.nodes import set_itself_enode

if __name__ == "__main__":
    print("Enter Node Num: ", end='')
    node_num = int(input())
    itself_enode = set_itself_enode(node_num)
    
    print(itself_enode)