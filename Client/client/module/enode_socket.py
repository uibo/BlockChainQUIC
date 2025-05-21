import socket

def make_connection_by_accept(enode: dict):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((enode["ip"], enode["port"]))
    tcp_socket.listen()
    conn, addr = tcp_socket.accept()
    return conn, addr

def make_connection_by_connect(itself_enode: dict, other_enode: dict):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((itself_enode["ip"], itself_enode["port"]))
    tcp_socket.connect((other_enode["ip"], other_enode["port"]))
    return tcp_socket

def make_connection_by_accept(port: int):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(("127.0.0.1", port))
    tcp_socket.listen()
    conn, addr = tcp_socket.accept()
    return conn, addr

 