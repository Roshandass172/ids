from web3 import Web3
import time

# Connect to Hardhat network
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# Contract details
contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
abi = [  # Full contract ABI
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "internalType": "uint256", "name": "attackId", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "ip", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "attackType", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "AttackLogged",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_attackId", "type": "uint256"},
            {"internalType": "string", "name": "_ip", "type": "string"},
            {"internalType": "string", "name": "_attackType", "type": "string"}
        ],
        "name": "logAttack",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getAttacks",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "attackId", "type": "uint256"},
                    {"internalType": "string", "name": "ip", "type": "string"},
                    {"internalType": "string", "name": "attackType", "type": "string"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
                ],
                "internalType": "struct AttackLogger.Attack[]",
                "name": "",
                "type": "tuple[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

contract = w3.eth.contract(address=contract_address, abi=abi)

# Event handler function
def handle_event(event):
    print(f"🚨 New Attack Logged! ID: {event['args']['attackId']}, IP: {event['args']['ip']}, Type: {event['args']['attackType']}")

# Create event filter
event_filter = w3.eth.filter({
    "address": contract_address,
    "topics": [w3.keccak(text="AttackLogged(uint256,string,string,uint256)").hex()]

})

print("🔍 Listening for attack logs...")

# Continuous event polling
while True:
    for event in event_filter.get_new_entries():
        handle_event(event)
    time.sleep(2)  # Prevent high CPU usage
