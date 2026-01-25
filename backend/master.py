import os
import subprocess
import time
import google.generativeai as genai

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MONITOR_PATH = os.path.join(BASE_DIR, "monitor.py")
REPLAY_PATH = os.path.join(BASE_DIR, "replay_attack.py")
LOG_FILE = os.path.join(BASE_DIR, "intrusion_logs.txt")

genai.configure(api_key="AIzaSyA2ewRhQsGEZ1F-ATd1-_aQcfvymreYY40")
model = genai.GenerativeModel("models/gemini-2.0-flash")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("=" * 55)
    print("        🛡 A_ura IDS CONTROL PANEL 🛡")
    print("=" * 55)

def menu():
    print("\nSelect an option:")
    print("1. ▶ Start Detection System")
    print("2. 🎥 Replay Attack Session")
    print("3. 📜 View Logs")
    print("4. 🤖 AI Assistance (Gemini)")
    print("5. ❌ Exit")

def start_detection():
    print("\nStarting IDS Engine...\n")
    subprocess.Popen(
        ["python", MONITOR_PATH],
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    input("IDS started. Press Enter to return...")

def replay_attack():
    file = input("Enter replay file name: ")
    path = os.path.join(BASE_DIR, file)

    if os.path.exists(path):
        subprocess.Popen(
            ["python", REPLAY_PATH, path],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        print("Replay file not found.")
    input("Press Enter...")

def view_logs():
    if not os.path.exists(LOG_FILE):
        print("No logs found.")
        input("Press Enter...")
        return

    print("\n--- LAST 20 LOG ENTRIES ---\n")
    with open(LOG_FILE, "r") as f:
        for line in f.readlines()[-20:]:
            print(line.strip())

    input("\nPress Enter...")

def ai_assistant():
    print("\n🤖 A_ura AI Assistant (Gemini)")
    print("Ask about attacks, IDS, honeypots, logs, replay.")
    print("Type 'exit' to return.\n")

    chat = model.start_chat(history=[])

    chat.send_message(
        "You are a cybersecurity assistant for an Intrusion Detection System project. "
        "Explain attacks, logs, honeypots, replay, and detection results simply."
    )

    while True:
        q = input("You: ")
        if q.lower() == "exit":
            break
        try:
            response = chat.send_message(q)
            print("A_ura:", response.text)
        except Exception as e:
            print("Gemini error:", e)

def main():
    while True:
        clear()
        banner()
        menu()
        choice = input("\nEnter choice: ")

        if choice == "1":
            start_detection()
        elif choice == "2":
            replay_attack()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            ai_assistant()
        elif choice == "5":
            print("Exiting...")
            time.sleep(1)
            break
        else:
            print("Invalid choice.")
            time.sleep(1)

if __name__ == "__main__":
    main()