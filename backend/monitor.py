import time
import threading
import numpy as np
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
from scapy.all import conf

# ======================================================
# CONFIG
# ======================================================

BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
ADMIN_CHAT_ID = 6838941898

INTERFACE = conf.iface



LOG_FILE = "intrusion_logs.txt"
MODEL_PATH = os.path.abspath("models/xgboost_intrusion_detection.json")

# ======================================================
# LOGGING
# ======================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ======================================================
# TELEGRAM BOT
# ======================================================

bot = telebot.TeleBot(BOT_TOKEN) if BOT_TOKEN else None

escape_markdown = lambda text: "".join(
    f"\\{char}" if char in "_*[]()~`>#+-=|{}.!" else char
    for char in text
)

def start_bot():
    if not bot:
        print("⚠ Telegram bot disabled (no token)")
        return
    print("🤖 Telegram bot polling started")
    bot.infinity_polling(skip_pending=True)

# ======================================================
# ML MODEL
# ======================================================

if not os.path.exists(MODEL_PATH):
    print(f"❌ Model not found at {MODEL_PATH}")
    sys.exit(1)

model = xgb.XGBClassifier()
model.load_model(MODEL_PATH)
print("✅ XGBoost model loaded")

# ======================================================
# FEATURE EXTRACTION
# ======================================================

def extract_features(packet):
    return {
        "duration": 0,
        "protocol_type": packet.proto,
        "service": 1 if packet.haslayer(scapy.TCP) else 2 if packet.haslayer(scapy.UDP) else 3,
        "flag": 1 if packet.haslayer(scapy.IP) else 0,
        "src_bytes": len(packet),
        "dst_bytes": len(packet.payload),

        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,

        "count": 0,
        "srv_count": 0,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 0,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,

        "dst_host_count": 0,
        "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }

# ======================================================
# PACKET PROCESSING
# ======================================================

def process_packet(packet):
    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    replay.log_event(src_ip, "Packet captured")

    # ---------- Custom test payloads ----------
    if packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)

        if b"###DOS_ATTACK###" in payload:
            score = deception.update_behavior(src_ip, "dos")
            replay.log_event(src_ip, "DoS detected", score)

            if deception.should_block(src_ip):
                replay.log_event(src_ip, "Blocked", score)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            return

        if b"###PORT_SCAN###" in payload:
            score = deception.update_behavior(src_ip, "port_scan")
            replay.log_event(src_ip, "Port scan detected", score)

            if deception.should_block(src_ip):
                replay.log_event(src_ip, "Blocked", score)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            return

    # ---------- ML detection ----------
    features = extract_features(packet)
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    if prediction == 1:
        score = deception.update_behavior(src_ip, "honeypot_hit")
        replay.log_event(src_ip, "ML flagged suspicious", score)

        alert = f"🚨 Suspicious activity from `{src_ip}`"
        logging.info(alert)

        if bot and ADMIN_CHAT_ID:
            try:
                bot.send_message(
                    ADMIN_CHAT_ID,
                    escape_markdown(alert),
                    parse_mode="MarkdownV2"
                )
            except Exception:
                pass

        if deception.should_block(src_ip):
            replay.log_event(src_ip, "Blocked", score)
            replay.save_session(src_ip)
            self_heal.isolate_threat(packet)

# ======================================================
# SNIFFER
# ======================================================

def start_sniffer():
    print(f"🔍 Network sniffer started on interface: {INTERFACE}")
    scapy.sniff(
        iface=INTERFACE,
        filter="ip",
        prn=process_packet,
        store=False
    )

# ======================================================
# IDS LIFECYCLE (USED BY FASTAPI)
# ======================================================

_running = False
_bot_thread = None
_sniff_thread = None

def start_ids():
    global _running, _bot_thread, _sniff_thread

    if _running:
        print("⚠ IDS already running")
        return

    print("🚀 Starting IDS Engine")
    _running = True

    honeynet.start_honeynet()

    _bot_thread = threading.Thread(
        target=start_bot,
        daemon=True
    )

    _sniff_thread = threading.Thread(
        target=start_sniffer,
        daemon=True
    )

    _bot_thread.start()
    _sniff_thread.start()

def stop_ids():
    global _running
    _running = False
    print("🛑 IDS stop requested (restart required to fully stop sniffing)")

def ids_status():
    return {
        "running": _running,
        "honeynet": True,
        "bot": _bot_thread.is_alive() if _bot_thread else False,
        "sniffer": _sniff_thread.is_alive() if _sniff_thread else False
    }
