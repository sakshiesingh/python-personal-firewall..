# Python Personal Firewall

A simple Python-based personal firewall simulation. Define custom rules to allow or block simulated network events, and log all actions.

## Features

- Add, list, and edit rules (block/allow by IP, port, protocol)
- Simulate network events (CLI)
- All blocked actions are logged
- Rules and logs saved in JSON and text files

## How to Use

1. **Clone this repository** or upload it to [Replit](https://replit.com/).
2. **Edit `rules.json`** to define firewall rules.
3. **Run `firewall.py`** in your Python environment or Replit.
4. **Use the CLI menu** to add rules, list rules, simulate events, and view logs.

## Example Rule

```json
[
    {"action": "block", "ip": "8.8.8.8"},
    {"action": "allow", "port": 443, "protocol": "TCP"}
]
