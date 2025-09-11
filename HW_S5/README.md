# Mock MCP (Safe Proof-of-Concept)

This project is a **safe educational demonstration** of insecure Model
Control Protocol (MCP) behaviors.\
It is intended for classroom use to **illustrate common security
issues** (SQL injection, unsafe file access, command execution) in a
controlled and harmless way.

------------------------------------------------------------------------

## ⚡ What it shows

-   **SQL Injection**: Constructs an unsafe SQL query string (but never
    executes it). Also shows the safe parameterized alternative.
-   **File Access**: Simulates insecure file reads but restricts access
    to a small whitelist of demo files.
-   **Command Execution**: Demonstrates command injection risks by
    returning *simulated* outputs instead of running real OS commands.

This allows you to explain vulnerabilities and mitigations without
risking any real exploitation.

------------------------------------------------------------------------

## 🚀 How to Run

### 1. Setup

``` bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# OR .\venv\Scripts\Activate.ps1   # Windows PowerShell

pip install fastapi uvicorn requests pydantic
```

### 2. Start the server

``` bash
uvicorn mock_mcp:app --reload --port 8000
```

You should see logs indicating the server is running on
`http://127.0.0.1:8000`.

### 3. Run the client

In another terminal (same venv):

``` bash
python client.py
```

------------------------------------------------------------------------

## ✅ Expected Output

When running `client.py`, you will see JSON responses such as:

-   **SQL Injection Demo**

``` json
{
  "note": "unsafe string is SHOWN but NOT executed. Use parameterized queries in real code.",
  "unsafe_query_example": "INSERT INTO records (name, address) VALUES ('Alice O'Connor', '1 Demo St')",
  "safe_parameterized_example": [
    "INSERT INTO records (name, address) VALUES (?, ?)",
    ["Alice O'Connor", "1 Demo St"]
  ]
}
```

-   **File Read Demo**

``` json
{
  "path": "/data/sample.txt",
  "content": "This is a safe demo file.\n"
}
```

-   **Command Execution Demo**

``` json
{
  "command": "whoami",
  "output": "demo_user",
  "note": "simulated output"
}
```

------------------------------------------------------------------------

## 🎯 Classroom Use

You can present this demo by: 1. Running the client and showing each
JSON response.\
2. Explaining how it relates to real vulnerabilities.\
3. Highlighting the safe mitigations (parameterized queries,
whitelisting, sandboxing).

This project is **safe by design** --- no real system commands or file
reads are executed.

------------------------------------------------------------------------

## 📌 Notes

-   For extra safety, you can run this inside a Docker container with
    networking disabled.\
-   This demo is **educational only** and not intended for production
    use.