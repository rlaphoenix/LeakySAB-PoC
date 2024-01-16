import socket
import threading


# Local Hostname and Port to bind the psuedo NNTP TCP server
NNTP_SERVER_LOCAL_HOST = ""    # "" = listen on all available interfaces
NNTP_SERVER_LOCAL_PORT = 8119  # 119=non-SSL + 8... = 8119, easier to remember


def start_nntp_server(host: str, port: int) -> None:
    """
    Host a basic TCP server that acts as a pseudo NNTP server.
    It's set up just enough to ask for authentication.
    It then just logs the received credentials.

    Note: This psuedo NNTP server does not support SSL.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.bind((host, port))
    s.listen(1)

    print(f"Listening on {host}:{port}")
    print("Ready for incoming connection tests.")

    while True:
        conn, addr = s.accept()
        with conn:
            data = None
            while not data:
                # sometimes needs a ton of tries, maybe even enough to break the connection
                # why? I have no idea
                conn.send(b"\x00")  # dunno but it works
                data = conn.recv(1024)
                if data:
                    break
            try:
                data = data.decode().strip()
                username = data.split(" ", maxsplit=2)[-1]
            except UnicodeDecodeError:
                print(f"[-] Failure on {addr}")
                print(" ∟ You likely have SSL checkbox ticked. Untick it.")
                continue

            conn.send(b"381")  # ask for password
            data = conn.recv(1024)
            if not data:
                break
            try:
                data = data.decode().strip()
                password = data.split(" ", maxsplit=2)[-1]
            except UnicodeDecodeError:
                print(f"[-] Failure on {addr}")
                print(" ∟ You likely have SSL checkbox ticked. Untick it.")
                continue

            print(f"[+] Success on {addr}")
            print(f" ∟ Username: {username}")
            print(f" ∟ Password: {password}")


def main():
    thread = threading.Thread(
        target=start_nntp_server,
        args=(NNTP_SERVER_LOCAL_HOST, NNTP_SERVER_LOCAL_PORT)
    )
    thread.start()


if __name__ == "__main__":
    main()
