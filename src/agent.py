from forta_agent import Finding, FindingType, FindingSeverity, get_json_rpc_url
from src.constants import CTOKEN_CONTRACTS, abi
import json
from web3 import Web3

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
abi = json.loads(abi)

all_last_rates = {}
for c_name, _ in CTOKEN_CONTRACTS.items():
    all_last_rates |= {c_name: 0}


def provide_handle_block(w3):
    def handle_block(block_event):

        findings = []

        for c_name, c_addr in CTOKEN_CONTRACTS.items():

            contract = web3.eth.contract(address=Web3.toChecksumAddress(c_addr), abi=abi)
            rate_current = contract.functions.exchangeRateCurrent().call()
            rate_last = all_last_rates.get(c_name, 0)

            if rate_current < rate_last:
                findings.append(Finding({
                    'name': 'CToken Exchange Rate Down',
                    'description': f'cToken {c_name} Exchange Rate Goes Down',
                    'alert_id': f'COMP_{c_name.capitalize()}_DOWN',
                    'type': FindingType.Suspicious,
                    'severity': FindingSeverity.Medium,
                }))

            all_last_rates[c_name] = rate_current

        return findings

    return handle_block


real_handle_block = provide_handle_block(web3)


def handle_block(block_event):
    return real_handle_block(block_event)
