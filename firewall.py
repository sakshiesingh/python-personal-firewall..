import json
import datetime
import os
from typing import Dict, List, Any, Union

RULES_FILE = 'rules.json'
LOG_FILE = 'firewall.log'


def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE) as f:
            return json.load(f)
    return []


def save_rules(rules):
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)


def log_event(event, reason):
    with open(LOG_FILE, "a") as logfile:
        logfile.write(f"{datetime.datetime.now()} - {event} - {reason}\n")


def match_rules(rules, event):
    for rule in rules:
        # Block/Allow by IP
        if rule.get("ip") and event.get("ip"):
            if event["ip"] == rule["ip"]:
                return rule["action"]
        # Block/Allow by port & protocol
        if rule.get("port") and event.get("port"):
            if event["port"] == rule["port"] and event.get(
                    "protocol", "").upper() == rule.get("protocol",
                                                        "").upper():
                return rule["action"]
    return "allow"  # Default action


def add_rule_cli(rules: List[Dict[str, Any]]) -> None:
    print("\nAdd a new rule:")
    action = input("Action (allow/block): ").strip().lower()
    ip = input("IP (leave blank to skip): ").strip()
    port_input = input("Port (leave blank to skip): ").strip()
    protocol = input(
        "Protocol (TCP/UDP, leave blank to skip): ").strip().upper()

    rule: Dict[str, Any] = {}
    rule["action"] = action
    if ip: 
        rule["ip"] = ip
    if port_input: 
        try:
            port_num = int(port_input)
            rule["port"] = port_num
        except ValueError:
            print("Invalid port number. Rule not added.")
            return
    if protocol: 
        rule["protocol"] = protocol
    rules.append(rule)
    save_rules(rules)
    print("Rule added!\n")


def list_rules_cli(rules):
    print("\nCurrent Rules:")
    for idx, rule in enumerate(rules, 1):
        print(f"{idx}. {rule}")
    print()


def simulate_packet_cli(rules):
    print("\nSimulate network event:")
    ip = input("Source/Dest IP: ").strip()
    port = int(input("Port: ").strip())
    protocol = input("Protocol (TCP/UDP): ").strip().upper()
    event = {"ip": ip, "port": port, "protocol": protocol}
    action = match_rules(rules, event)
    if action == "block":
        log_event(event, "Blocked by rule")
        print(f"Blocked: {event}")
    else:
        print(f"Allowed: {event}")


def view_log_cli():
    print("\n--- Firewall Log ---")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            print(f.read())
    else:
        print("No log entries yet.")
    print("--------------------\n")


def main():
    print("Welcome to the Python Personal Firewall (Interactive CLI)")
    rules = load_rules()

    while True:
        print("Menu:")
        print("1. Add rule")
        print("2. List rules")
        print("3. Simulate network event")
        print("4. View firewall log")
        print("5. Exit")
        choice = input("Choose an option (1-5): ").strip()
        if choice == '1':
            add_rule_cli(rules)
        elif choice == '2':
            list_rules_cli(rules)
        elif choice == '3':
            simulate_packet_cli(rules)
        elif choice == '4':
            view_log_cli()
        elif choice == '5':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.\n")


if __name__ == "__main__":
    main()
