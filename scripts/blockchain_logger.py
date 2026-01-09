from web3 import Web3
import json

# Connect to Local Ethereum Node (Ganache/Hardhat)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# Smart contract details
contract_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

with open("artifacts/contracts/attack_logger.sol/AttackLogger.json") as f:
    contract_abi = json.load(f)

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def log_attack(attack_id, ip, attack_type):
    tx = contract.functions.logAttack(attack_id, ip, attack_type).transact({"from": w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print(f"🛡️ Attack Logged on Blockchain: {receipt.transactionHash.hex()}")
