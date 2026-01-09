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

BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
ADMIN_CHAT_ID = 6838941898
bot = telebot.TeleBot(BOT_TOKEN)

LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

MODEL_PATH = os.path.abspath("../models/xgboost_intrusion_detection.json")
if os.path.exists(MODEL_PATH):
    model = xgb.XGBClassifier()
    model.load_model(MODEL_PATH)
    print("✅ Model Loaded Successfully!")
else:
    print(f"❌ Model file not found at {MODEL_PATH}")
    sys.exit(1)

escape_markdown = lambda text: "".join(f"\\{char}" if char in "_*[]()~`>#+-=|{}.!" else char for char in text)

def extract_features(packet):
    return {
        "duration": 0,
        "protocol_type": packet.proto,
        "service": 1 if packet.haslayer(scapy.TCP) else 2 if packet.haslayer(scapy.UDP) else 3,
        "flag": 1 if packet.haslayer(scapy.IP) else 0,
        "src_bytes": len(packet),
        "dst_bytes": len(packet.payload),
        "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0,
        "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0,
        "count": 0, "srv_count": 0,
        "serror_rate": 0, "srv_serror_rate": 0,
        "rerror_rate": 0, "srv_rerror_rate": 0,
        "same_srv_rate": 0, "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 0, "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }

def process_packet(packet):
    print(f"📡 Captured Packet: {packet.summary()}")

    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    replay.log_event(src_ip, "Packet captured")

    if packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)

        if b"###DOS_ATTACK###" in payload:
            score = deception.update_behavior(src_ip, "dos")
            replay.log_event(src_ip, "DoS detected", score)

            if deception.should_block(src_ip):
                replay.log_event(src_ip, "Threat blocked", score)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            else:
                replay.log_event(src_ip, "Observed via honeynet", score)
            return

        elif b"###PORT_SCAN###" in payload:
            score = deception.update_behavior(src_ip, "port_scan")
            replay.log_event(src_ip, "Port scan detected", score)

            if deception.should_block(src_ip):
                replay.log_event(src_ip, "Threat blocked", score)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            else:
                replay.log_event(src_ip, "Observed via honeynet", score)
            return

    features = extract_features(packet)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]

    if prediction == 1:
        score = deception.update_behavior(src_ip, "honeypot_hit")
        replay.log_event(src_ip, "ML flagged suspicious", score)

        alert_msg = f"🚨 *Suspicious Activity Observed* `{src_ip}`"
        logging.info(alert_msg)

        try:
            bot.send_message(ADMIN_CHAT_ID, escape_markdown(alert_msg), parse_mode="MarkdownV2")
        except Exception:
            pass

        if deception.should_block(src_ip):
            replay.log_event(src_ip, "Threat blocked", score)
            replay.save_session(src_ip)
            self_heal.isolate_threat(packet)

@bot.message_handler(commands=["start"])
def start(message):
    bot.send_message(message.chat.id, escape_markdown("🤖 *A_ura_bot Activated!*"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["status"])
def status(message):
    bot.send_message(message.chat.id, escape_markdown("✅ *IDS System is Running!*"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["help"])
def help(message):
    bot.send_message(message.chat.id, escape_markdown("Use /status to check system health"), parse_mode="MarkdownV2")

def start_bot():
    print("🤖 A_ura_bot is now active!")
    bot.infinity_polling(timeout=10, long_polling_timeout=5)

def start_sniffer():
    print("🔍 Monitoring Network Traffic in Real Time...")
    scapy.sniff(filter="ip", prn=process_packet, store=0)

honeynet.start_honeynet()

bot_thread = threading.Thread(target=start_bot, daemon=True)
sniff_thread = threading.Thread(target=start_sniffer, daemon=True)

bot_thread.start()
sniff_thread.start()

bot_thread.join()
