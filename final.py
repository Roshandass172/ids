import time
import threading
import json
import scapy.all as scapy
import logging
import telebot
import os
import sys
import matplotlib.pyplot as plt
import networkx as nx

import self_heal
import honeynet
import replay_logger as replay
import decision_engine as decision

from pipeline import CryptonPipeline

# ================= CONFIG =================

MY_IP = "10.7.68.114"

BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
ADMIN_CHAT_ID = 6838941898
bot = telebot.TeleBot(BOT_TOKEN)

LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(message)s")

iface_name = "Wi-Fi"   # change if needed

# =========================================

escape_markdown = lambda t: "".join(f"\\{c}" if c in "_*[]()~`>#+-=|{}.!" else c for c in t)

blocked_ips = set()
monitoring_paused = False
_running = False

# ================= PIPELINE =================

pipeline = CryptonPipeline(device="cpu")

# Check terminal flag
VISUAL_MODE = "--visual" in sys.argv

# =========================================

def visualize_graph():
    graph = pipeline.graph_engine.get_graph()

    if graph.number_of_nodes() == 0:
        return

    plt.clf()
    pos = nx.spring_layout(graph)

    nx.draw(graph, pos, with_labels=True,
            node_color="lightgreen",
            node_size=1200,
            edge_color="gray")

    edge_labels = nx.get_edge_attributes(graph, "count")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels)

    plt.title("CRYPTON-X Network Graph (GNN Input)")
    plt.pause(0.01)


def print_pipeline_output(result):
    print("\n🧠 PIPELINE OUTPUT")
    print("────────────────────────────")
    print(f"IP            : {result['ip']}")
    print(f"GNN→Transformer Attack Prob : {round(result['attack_prob'],3)}")
    print(f"Stage         : {result['stage']}")
    print(f"Campaign      : {result['campaign_stage']}")
    print(f"Severity      : {result['severity']}")
    print(f"Action        : {result['action']}")
    print("Pipeline Path : Packet → Graph → GNN → Transformer → Campaign → Decision")
    print("────────────────────────────")


def process_packet(packet):
    global monitoring_paused

    if monitoring_paused or not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    pkt_size = len(packet)

    if src_ip == MY_IP or src_ip.startswith("127.") or src_ip == "0.0.0.0":
        return

    if src_ip in blocked_ips:
        self_heal.isolate_threat(packet)
        return

    result = pipeline.process_packet(src_ip, dst_ip, pkt_size)

    if not result:
        return

    severity = result["severity"]
    action = result["action"]
    stage = result["stage"]
    campaign = result["campaign_stage"]
    attack_prob = result["attack_prob"]

    explanation = f"Prob={round(attack_prob,3)}, Stage={stage}, Campaign={campaign}"

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

    # ================= VISUAL MODE =================
    if VISUAL_MODE:
        print_pipeline_output(result)
        visualize_graph()

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

# ================= START IDS =================

def start_ids():
    global _running
    if _running:
        return
    _running = True

    honeynet.start_honeynet()

    if VISUAL_MODE:
        plt.ion()
        print("📊 VISUAL MODE ENABLED (Graph + Pipeline Output)")

    threading.Thread(
        target=lambda: scapy.sniff(
            iface=iface_name,
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
