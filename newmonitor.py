import time
import threading
import json
import scapy.all as scapy
import logging
import telebot
import os
import sys

import self_heal
import honeynet
import replay_logger as replay
import decision_engine as decision

from pipeline import CryptonPipeline

# ================= CONFIG =================

MY_IP = "10.7.68.114"

BOT_TOKEN = "YOUR_BOT_TOKEN"
ADMIN_CHAT_ID = 123456789

LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# =========================================

escape_markdown = lambda t: "".join(f"\\{c}" if c in "_*[]()~`>#+-=|{}.!" else c for c in t)

blocked_ips = set()
monitoring_paused = False
_running = False

bot = telebot.TeleBot(BOT_TOKEN)

# ================= PIPELINE =================

pipeline = CryptonPipeline(device="cpu")

# =========================================

def build_explanation(result):
    return (
        f"AttackProb={round(result['attack_prob'],3)}, "
        f"Stage={result['stage']}, "
        f"Campaign={result['campaign_stage']}"
    )

def process_packet(packet):
    global monitoring_paused

    if monitoring_paused or not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    pkt_size = len(packet)

    # Ignore own traffic
    if src_ip == MY_IP:
        return

    if src_ip.startswith("127.") or src_ip == "0.0.0.0":
        return

    # Already blocked
    if src_ip in blocked_ips:
        self_heal.isolate_threat(packet)
        return

    # Run through pipeline
    result = pipeline.process_packet(src_ip, dst_ip, pkt_size)

    if not result:
        return

    severity = result["severity"]
    action = result["action"]
    stage = result["stage"]
    campaign = result["campaign_stage"]
    attack_prob = result["attack_prob"]

    explanation = build_explanation(result)

    # ================= LOG =================

    replay.log_event(
        src_ip,
        "Attack detected",
        confidence=attack_prob,
        severity=severity,
        decision=action,
        category=campaign,
        stage=stage,
        explanation=explanation
    )

    logging.info(f"{severity} {src_ip} {action} | {explanation}")

    # ================= TELEGRAM ALERT =================

    try:
        bot.send_message(
            ADMIN_CHAT_ID,
            escape_markdown(
                f"🚨 {severity} Threat\n"
                f"IP: `{src_ip}`\n"
                f"Stage: {stage}\n"
                f"Campaign: {campaign}\n"
                f"Decision: {action}\n"
                f"Reason: {explanation}"
            ),
            parse_mode="MarkdownV2"
        )
    except:
        pass

    # ================= RESPONSE =================

    if action == "BLOCK":
        blocked_ips.add(src_ip)
        replay.save_session(src_ip)
        self_heal.isolate_threat(packet)

# ================= TELEGRAM COMMANDS =================

@bot.message_handler(commands=["pause"])
def pause_cmd(m):
    global monitoring_paused
    monitoring_paused = True
    bot.send_message(m.chat.id, escape_markdown("Monitoring paused"),
                     parse_mode="MarkdownV2")

@bot.message_handler(commands=["resume"])
def resume_cmd(m):
    global monitoring_paused
    monitoring_paused = False
    bot.send_message(m.chat.id, escape_markdown("Monitoring resumed"),
                     parse_mode="MarkdownV2")

@bot.message_handler(commands=["logs"])
def logs_cmd(message):
    session_file = replay.get_last_session_file()

    if not session_file or not os.path.exists(session_file):
        bot.send_message(message.chat.id,
                         escape_markdown("No active replay available"),
                         parse_mode="MarkdownV2")
        return

    with open(session_file, "r") as f:
        data = json.load(f)

    out = ""
    for e in data["timeline"][-10:]:
        out += f"[{e['timestamp']}]\n"
        out += f"Stage     : {e.get('stage')}\n"
        out += f"Campaign  : {e.get('category')}\n"
        out += f"Severity  : {e.get('severity')}\n"
        out += f"Confidence: {e.get('confidence')}\n"
        out += f"Decision  : {e.get('decision')}\n"
        out += f"Reason    : {e.get('explanation')}\n\n"

    bot.send_message(message.chat.id, escape_markdown(out), parse_mode="MarkdownV2")

# ================= START IDS =================

def start_ids():
    global _running
    if _running:
        return
    _running = True

    honeynet.start_honeynet()

    threading.Thread(target=bot.infinity_polling, daemon=True).start()

    threading.Thread(
        target=lambda: scapy.sniff(
            iface="Wi-Fi",
            filter="ip",
            prn=process_packet,
            store=0
        ),
        daemon=True
    ).start()

if __name__ == "__main__":
    start_ids()
    while True:
        time.sleep(1)
