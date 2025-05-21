import sys
import socket
from config.nodes import NODES

if __name__ == "__main__":
    node_num = int(sys.argv[1])
    SELF = NODES[node_num]
    NODES.remove(NODES[node_num])
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((SELF[1], SELF[2]))
    tcp_socket.listen()
    print(f"Listening on 127.0.0.1:{SELF[2]}")
    conn, addr = tcp_socket.accept()
    print(f"Accepted connection from {addr}")
