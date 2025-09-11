# client.py
import requests, json

BASE = "http://localhost:8000"

def demo_insert():
    payload = {"name": "Alice O'Connor", "address": "1 Demo St"}
    r = requests.post(f"{BASE}/tools/insert_record", json=payload)
    print("insert_record response:")
    print(json.dumps(r.json(), indent=2))

def demo_read():
    payload = {"path": "/data/sample.txt"}
    r = requests.post(f"{BASE}/tools/read_file", json=payload)
    print("\nread_file response:")
    print(json.dumps(r.json(), indent=2))

def demo_cmd():
    payload = {"command": "whoami"}
    r = requests.post(f"{BASE}/tools/execute_command", json=payload)
    print("\nexecute_command response:")
    print(json.dumps(r.json(), indent=2))

if __name__ == "__main__":
    demo_insert()
    demo_read()
    demo_cmd()
