import socket
import threading
import logging
from datetime import datetime

HONEYPOT_LOG = "honeynet_logs.txt"
logging.basicConfig(
    filename=HONEYPOT_LOG,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def ssh_honeypot(port=2222):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"🍯 SSH Honeypot listening on port {port}")

    while True:
        conn, addr = s.accept()
        ip, src_port = addr
        print(f"🍯 SSH Honeypot hit from {ip}:{src_port}")
        logging.info(f"SSH_HONEYPOT_HIT from {ip}:{src_port}")

        conn.send(b"SSH-2.0-OpenSSH_7.4\r\n")
        conn.close()

def http_honeypot(port=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"🍯 HTTP Honeypot listening on port {port}")

    while True:
        conn, addr = s.accept()
        ip, src_port = addr
        request = conn.recv(1024).decode(errors="ignore")

        print(f"🍯 HTTP Honeypot hit from {ip}:{src_port}")
        logging.info(f"HTTP_HONEYPOT_HIT from {ip}:{src_port} | Request: {request[:100]}")

        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.49\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><body><h1>It works!</h1></body></html>"
        )
        conn.send(response.encode())
        conn.close()

def ftp_honeypot(port=2121):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"🍯 FTP Honeypot listening on port {port}")

    while True:
        conn, addr = s.accept()
        ip, src_port = addr
        print(f"🍯 FTP Honeypot hit from {ip}:{src_port}")
        logging.info(f"FTP_HONEYPOT_HIT from {ip}:{src_port}")

        conn.send(b"220 FTP Server Ready\r\n")
        conn.close()

def start_honeynet():
    print("🕸️ Honeynet initializing...")

    threading.Thread(target=ssh_honeypot, daemon=True).start()
    threading.Thread(target=http_honeypot, daemon=True).start()
    threading.Thread(target=ftp_honeypot, daemon=True).start()

    print("✅ Honeynet is ACTIVE (SSH, HTTP, FTP)")

if __name__ == "__main__":
    start_honeynet()
    while True:
        pass
