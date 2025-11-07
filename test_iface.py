import socket
import sys

def bind_socket_to_iface(sock: socket.socket, ifname: str):
    if sys.platform == "darwin":
        ifindex = socket.if_nametoindex(ifname)
        level = socket.IPPROTO_IPV6 if sock.family == socket.AF_INET6 else socket.IPPROTO_IP
        optname = 125 if sock.family == socket.AF_INET6 else 25 # IPV6_BOUND_IF / IP_BOUND_IF
        sock.setsockopt(level, optname, ifindex)
    elif sys.platform.startswith("linux"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())

def send_http_request(interface: str, host: str, port: int = 80, type: int = socket.AF_INET):
    with socket.socket(type, socket.SOCK_STREAM) as s:
        bind_socket_to_iface(s, interface)

        print(f"[+] Connecting to {host}:{port} ...")
        s.connect((host, port))

        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())

        print("[+] Response:")
        while True:
            data = s.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    try:
        send_http_request(interface, "api.ipify.org", type=socket.AF_INET)
    except Exception as e:
        print(f"IPv4 doesn't work")
    print()
    try:
        send_http_request(interface, "api64.ipify.org", type=socket.AF_INET6)
    except Exception as e:
        print(f"IPv6 doesn't work")
    print()
