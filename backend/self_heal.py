import os
import time
import subprocess

def isolate_threat(packet):
    """Isolates the attacker's IP by blocking it using Windows Defender Firewall."""
    if packet.haslayer("IP"):
        attacker_ip = packet["IP"].src
        print(f"⚠️ Isolating Threat from {attacker_ip}...")

        # Block the attacker using Windows Firewall
        os.system(f'netsh advfirewall firewall add rule name="Block {attacker_ip}" dir=in action=block remoteip={attacker_ip}')
        print(f"❌ Blocked IP: {attacker_ip}")

        # Schedule auto-recovery
        time.sleep(60)  # Unblock after 60 seconds
        os.system(f'netsh advfirewall firewall delete rule name="Block {attacker_ip}"')
        print(f"✅ Auto-Healed: {attacker_ip} is unblocked!")

print("✅ Self-Healing System Ready!")
