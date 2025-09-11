# mock_mcp.py  (SAFE educational PoC)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock MCP (SAFE PoC)")

# ----- simulated file store (whitelist only) -----
SAMPLE_FILES = {
    "/app/config.yaml": "app_key: REDACTED\nmode: demo\n",
    "/data/sample.txt": "This is a safe demo file.\n"
}

# ----- simulated command outputs (NO real execution) -----
SIMULATED_COMMANDS = {
    "whoami": "demo_user",
    "uname -a": "DemoOS 1.0 (simulated)",
}

# ----- models -----
class InsertRecord(BaseModel):
    name: str
    address: str

class ReadFile(BaseModel):
    path: str

class ExecCmd(BaseModel):
    command: str

# ----- endpoints -----
@app.post("/tools/insert_record")
def insert_record(payload: InsertRecord):
    """
    Demonstrates how an *unsafe* SQL string would be constructed (returned for demo only)
    and also returns the safe parameterized query.
    NOTE: The unsafe string is NOT executed in this demo.
    """
    unsafe_query = f"INSERT INTO records (name, address) VALUES ('{payload.name}', '{payload.address}')"
    safe_query = ("INSERT INTO records (name, address) VALUES (?, ?)", (payload.name, payload.address))
    return {
        "note": "unsafe string is SHOWN but NOT executed. Use parameterized queries in real code.",
        "unsafe_query_example": unsafe_query,
        "safe_parameterized_example": safe_query,
    }

@app.post("/tools/read_file")
def read_file(payload: ReadFile):
    """Only return content for whitelisted demo paths."""
    if payload.path in SAMPLE_FILES:
        return {"path": payload.path, "content": SAMPLE_FILES[payload.path]}
    raise HTTPException(status_code=403, detail="Path not allowed in this demo")

@app.post("/tools/execute_command")
def execute_command(payload: ExecCmd):
    """DO NOT execute commands. Return simulated output or a safe message."""
    out = SIMULATED_COMMANDS.get(payload.command)
    if out:
        return {"command": payload.command, "output": out, "note": "simulated output"}
    return {
        "command": payload.command,
        "output": f"(simulated) running '{payload.command}' is disabled in this demo",
        "note": "commands are not executed for safety"
    }

@app.get("/tools/list_demo_items")
def list_items():
    return {
        "available_files": list(SAMPLE_FILES.keys()),
        "simulated_commands": list(SIMULATED_COMMANDS.keys())
    }
