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
import decision_engine as decision
from collections import defaultdict

BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
ADMIN_CHAT_ID = 6838941898
bot = telebot.TeleBot(BOT_TOKEN)

LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

MODEL_PATH = os.path.abspath("../models/xgboost_intrusion_detection.json")
if os.path.exists(MODEL_PATH):
    model = xgb.XGBClassifier()
    model.load_model(MODEL_PATH)
else:
    sys.exit(1)

escape_markdown = lambda text: "".join(f"\\{c}" if c in "_*[]()~`>#+-=|{}.!" else c for c in text)

ip_triggers = defaultdict(set)
blocked_ips = set()
monitoring_paused = False

_running = False
_bot_thread = None
_sniff_thread = None

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

def process_packet(packet):
    global monitoring_paused

    if monitoring_paused:
        return

    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src

    if src_ip in blocked_ips:
        self_heal.isolate_threat(packet)
        return

    replay.log_event(src_ip, "Packet captured")

    if packet.haslayer(scapy.Raw):
        payload = bytes(packet[scapy.Raw].load)

        if b"###DOS_ATTACK###" in payload:
            ip_triggers[src_ip].add("DoS")
            score = deception.update_behavior(src_ip, "dos")
            severity = decision.get_severity(score)
            action = decision.get_decision(score)
            replay.log_event(src_ip, f"DoS | {severity} | {action}", score)
            logging.info(f"{severity} DoS {src_ip} {action}")

            if action == "BLOCK":
                blocked_ips.add(src_ip)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            return

        if b"###PORT_SCAN###" in payload:
            ip_triggers[src_ip].add("Port Scan")
            score = deception.update_behavior(src_ip, "port_scan")
            severity = decision.get_severity(score)
            action = decision.get_decision(score)
            replay.log_event(src_ip, f"PortScan | {severity} | {action}", score)
            logging.info(f"{severity} PortScan {src_ip} {action}")

            if action == "BLOCK":
                blocked_ips.add(src_ip)
                replay.save_session(src_ip)
                self_heal.isolate_threat(packet)
            return

    features = extract_features(packet)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]

    if prediction == 1:
        ip_triggers[src_ip].add("Honeypot")
        score = deception.update_behavior(src_ip, "honeypot_hit")
        severity = decision.get_severity(score)
        action = decision.get_decision(score)
        replay.log_event(src_ip, f"ML | {severity} | {action}", score)
        logging.info(f"{severity} ML {src_ip} {action}")

        msg = f"🚨 *{severity} Threat* `{src_ip}` | Decision: {action}"
        try:
            bot.send_message(ADMIN_CHAT_ID, escape_markdown(msg), parse_mode="MarkdownV2")
        except:
            pass

        if action == "BLOCK":
            blocked_ips.add(src_ip)
            replay.save_session(src_ip)
            self_heal.isolate_threat(packet)

@bot.message_handler(commands=["logs"])
def logs(message):
    try:
        with open(LOG_FILE) as f:
            data = f.readlines()[-10:]
        bot.send_message(message.chat.id, escape_markdown("".join(data)), parse_mode="MarkdownV2")
    except:
        bot.send_message(message.chat.id, escape_markdown("No logs available"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["full_logs"])
def full_logs(message):
    try:
        with open(LOG_FILE) as f:
            data = f.readlines()
        chunk = ""
        for line in data:
            if len(chunk) + len(line) > 3500:
                bot.send_message(message.chat.id, escape_markdown(chunk), parse_mode="MarkdownV2")
                chunk = ""
            chunk += line
        if chunk:
            bot.send_message(message.chat.id, escape_markdown(chunk), parse_mode="MarkdownV2")
    except:
        pass

@bot.message_handler(commands=["block"])
def block_ip(message):
    try:
        ip = message.text.split()[1]
        blocked_ips.add(ip)
        bot.send_message(message.chat.id, escape_markdown(f"IP `{ip}` blocked"), parse_mode="MarkdownV2")
    except:
        pass

@bot.message_handler(commands=["unblock"])
def unblock_ip(message):
    try:
        ip = message.text.split()[1]
        blocked_ips.discard(ip)
        bot.send_message(message.chat.id, escape_markdown(f"IP `{ip}` unblocked"), parse_mode="MarkdownV2")
    except:
        pass

@bot.message_handler(commands=["pause"])
def pause_monitoring(message):
    global monitoring_paused
    monitoring_paused = True
    bot.send_message(message.chat.id, escape_markdown("Monitoring paused"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["resume"])
def resume_monitoring(message):
    global monitoring_paused
    monitoring_paused = False
    bot.send_message(message.chat.id, escape_markdown("Monitoring resumed"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["stats"])
def stats(message):
    text = (
        f"Tracked IPs: {len(deception.ip_scores)}\n"
        f"Blocked IPs: {len(blocked_ips)}\n"
        f"Monitoring: {'Paused' if monitoring_paused else 'Active'}"
    )
    bot.send_message(message.chat.id, escape_markdown(text), parse_mode="MarkdownV2")

def _start_bot():
    bot.infinity_polling(timeout=10, long_polling_timeout=5)

def _start_sniffer():
    scapy.sniff(filter="ip", prn=process_packet, store=0)

def start_ids():
    global _running, _bot_thread, _sniff_thread

    if _running:
        return

    _running = True
    honeynet.start_honeynet()

    _bot_thread = threading.Thread(target=_start_bot, daemon=True)
    _sniff_thread = threading.Thread(target=_start_sniffer, daemon=True)

    _bot_thread.start()
    _sniff_thread.start()

def stop_ids():
    global _running
    _running = False

def ids_status():
    return {
        "running": _running,
        "bot": _bot_thread.is_alive() if _bot_thread else False,
        "sniffer": _sniff_thread.is_alive() if _sniff_thread else False,
        "honeynet": True
    }
