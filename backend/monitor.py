import time
import threading
import json
import scapy.all as scapy
import xgboost as xgb
import pandas as pd
import self_heal
import sys
import os
import logging
import telebot
import honeynet
import deception_engine as deception
import replay_logger as replay
import decision_engine as decision
from collections import defaultdict

BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
ADMIN_CHAT_ID = 6838941898
bot = telebot.TeleBot(BOT_TOKEN)

LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

MODEL_PATH = os.path.abspath("../models/xgboost_intrusion_detection.json")
if not os.path.exists(MODEL_PATH):
    sys.exit(1)

model = xgb.XGBClassifier()
model.load_model(MODEL_PATH)

escape_markdown = lambda t: "".join(f"\\{c}" if c in "_*[]()~`>#+-=|{}.!" else c for c in t)

blocked_ips = set()
monitoring_paused = False
_running = False

CATEGORY_MAP = {
    "dos": "Flooding",
    "port_scan": "Reconnaissance",
    "honeypot_hit": "Exploitation",
    "breakthrough": "Brute Force"
}

def get_category(behavior):
    return CATEGORY_MAP.get(behavior, "Unknown")

def extract_features(packet):
    return {k: 0 for k in model.get_booster().feature_names}

def process_packet(packet):
    global monitoring_paused

    if monitoring_paused or not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src

    if src_ip in blocked_ips:
        self_heal.isolate_threat(packet)
        return

    replay.log_event(src_ip, "Packet captured")

    if packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)

        behavior = None
        if b"###DOS_ATTACK###" in payload:
            behavior = "dos"
        elif b"###PORT_SCAN###" in payload:
            behavior = "port_scan"

        if behavior:
            confidence = deception.update_behavior(src_ip, behavior)
            category = get_category(behavior)
            severity = decision.get_severity(confidence, category)
            action = decision.get_decision(confidence, category)

            replay.log_event(
                src_ip,
                "Attack detected",
                confidence=confidence,
                severity=severity,
                decision=action,
                category=category
            )

            logging.info(f"{severity} {category} {src_ip} {action}")

            if action == "BLOCK":
                blocked_ips.add(src_ip)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            return

    df = pd.DataFrame([extract_features(packet)])
    if model.predict(df)[0] == 1:
        confidence = deception.update_behavior(src_ip, "honeypot_hit")
        category = get_category("honeypot_hit")
        severity = decision.get_severity(confidence, category)
        action = decision.get_decision(confidence, category)

        replay.log_event(
            src_ip,
            "ML flagged",
            confidence=confidence,
            severity=severity,
            decision=action,
            category=category
        )

        logging.info(f"{severity} {category} {src_ip} {action}")

        try:
            bot.send_message(
                ADMIN_CHAT_ID,
                escape_markdown(
                    f"🚨 {severity} Threat\n"
                    f"IP: `{src_ip}`\n"
                    f"Category: {category}\n"
                    f"Decision: {action}"
                ),
                parse_mode="MarkdownV2"
            )
        except:
            pass

        if action == "BLOCK":
            blocked_ips.add(src_ip)
            replay.save_session(src_ip)
            self_heal.isolate_threat(packet)

@bot.message_handler(commands=["logs"])
def logs_cmd(message):
    session_file = replay.get_last_session_file()

    if not session_file or not os.path.exists(session_file):
        bot.send_message(message.chat.id, escape_markdown("No active attack replay available"), parse_mode="MarkdownV2")
        return

    with open(session_file, "r") as f:
        events = json.load(f)

    out = ""
    for e in events[-10:]:
        out += f"[{e['timestamp']}]\n"
        out += f"Event     : {e['event']}\n"
        if e.get("category"):
            out += f"Category  : {e['category']}\n"
        if e.get("severity"):
            out += f"Severity  : {e['severity']}\n"
        if e.get("confidence") is not None:
            out += f"Confidence: {round(e['confidence'], 3)}\n"
        if e.get("decision"):
            out += f"Decision  : {e['decision']}\n"
        out += "\n"

    bot.send_message(message.chat.id, escape_markdown(out), parse_mode="MarkdownV2")

@bot.message_handler(commands=["block"])
def block_cmd(m):
    ip = m.text.split(maxsplit=1)[1]
    blocked_ips.add(ip)
    bot.send_message(m.chat.id, escape_markdown(f"Blocked `{ip}`"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["unblock"])
def unblock_cmd(m):
    ip = m.text.split(maxsplit=1)[1]
    blocked_ips.discard(ip)
    bot.send_message(m.chat.id, escape_markdown(f"Unblocked `{ip}`"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["pause"])
def pause_cmd(m):
    global monitoring_paused
    monitoring_paused = True
    bot.send_message(m.chat.id, escape_markdown("Monitoring paused"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["resume"])
def resume_cmd(m):
    global monitoring_paused
    monitoring_paused = False
    bot.send_message(m.chat.id, escape_markdown("Monitoring resumed"), parse_mode="MarkdownV2")

def start_ids():
    global _running
    if _running:
        return
    _running = True
    honeynet.start_honeynet()
    threading.Thread(target=bot.infinity_polling, daemon=True).start()
    threading.Thread(
        target=lambda: scapy.sniff(iface="Wi-Fi", filter="ip", prn=process_packet, store=0),
        daemon=True
    ).start()

if __name__ == "__main__":
    start_ids()
    while True:
        time.sleep(1)
