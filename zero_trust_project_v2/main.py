import json
import os
from datetime import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ZERO TRUST: LOAD POLICIES
def load_policies():
    with open("policies.json", "r") as f:
        return json.load(f)

# ZERO TRUST: CHECK PERMISSION
def check_permission(function_name):
    policies = load_policies()
    is_allowed = policies.get(function_name, {}).get("allowed", False)
    
    # LOG EVERYTHING
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "function": function_name,
        "decision": "ALLOWED" if is_allowed else "BLOCKED"
    }
    with open("audit_log.txt", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    return is_allowed

# FUNCTIONS
def read_file(filename):
    """Actually reads a real file"""
    try:
        with open(filename, "r") as f:
            content = f.read()
        return f"File content: {content}"
    except Exception as e:
        return f"Error reading file: {e}"

def write_file(filename, content):
    """Actually writes to a real file"""
    try:
        with open(filename, "w") as f:
            f.write(content)
        return f"Successfully wrote to {filename}"
    except Exception as e:
        return f"Error writing file: {e}"

def delete_file(filename):
    """Actually deletes a real file"""
    try:
        os.remove(filename)
        return f"Successfully deleted {filename}"
    except Exception as e:
        return f"Error deleting file: {e}"

# EXECUTE WITH ZERO TRUST
def execute_function(function_name, arguments):
    """
    Zero Trust Enforcement:
    1. Check policy
    2. Execute ONLY if allowed
    3. Return result or denial
    """
    print(f"\n🔍 Checking permission for: {function_name}")
    
    if not check_permission(function_name):
        msg = f"❌ BLOCKED: {function_name} not allowed by policy"
        print(msg)
        return msg
    
    print(f"✅ ALLOWED: Executing {function_name}")
    
    # Execute the actual function
    if function_name == "read_file":
        return read_file(arguments["filename"])
    elif function_name == "write_file":
        return write_file(arguments["filename"], arguments["content"])
    elif function_name == "delete_file":
        return delete_file(arguments["filename"])
    else:
        return "Unknown function"

# DEFINE TOOLS FOR CLAUDE
tools = [
    {
        "name": "read_file",
        "description": "Read contents of a file",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Path to file"}
            },
            "required": ["filename"]
        }
    },
    {
        "name": "write_file",
        "description": "Write content to a file",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Path to file"},
                "content": {"type": "string", "description": "Content to write"}
            },
            "required": ["filename", "content"]
        }
    },
    {
        "name": "delete_file",
        "description": "Delete a file",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Path to file"}
            },
            "required": ["filename"]
        }
    }
]

# MAIN
def run_agent(user_request):
    print(f"\n{'='*60}")
    print(f"USER REQUEST: {user_request}")
    print(f"{'='*60}")
    
    # Ask Claude what to do
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        tools=tools,
        messages=[{"role": "user", "content": user_request}]
    )
    
    # Check if Claude wants to use a tool
    if response.stop_reason == "tool_use":
        tool_use = next(block for block in response.content if block.type == "tool_use")
        
        print(f"\n🤖 Claude wants to call: {tool_use.name}")
        print(f"   With arguments: {tool_use.input}")
        
        # ZERO TRUST CHECKPOINT: Check before executing
        result = execute_function(tool_use.name, tool_use.input)
        print(f"\n📊 Result: {result}")
        
        return result
    else:
        # Claude responded without using tools
        print(f"\n💬 Claude says: {response.content[0].text}")
        return response.content[0].text

# DEMO SCENARIOS
# ======================
if __name__ == "__main__":
    print("\n🛡️  ZERO TRUST AI AGENT - LIVE DEMO\n")
    
    # Create a test file first
    with open("test.txt", "w") as f:
        f.write("This is test data")
    
    # Test 1: Read file (should be allowed)
    print("\n--- TEST 1: Read File ---")
    run_agent("Read the file test.txt")
    
    # Test 2: Try to delete (should be blocked)
    print("\n\n--- TEST 2: Delete File ---")
    run_agent("Delete the file test.txt")
    
    # Test 3: Write file (depends on your policy)
    print("\n\n--- TEST 3: Write File ---")
    run_agent("Write 'Hello World' to output.txt")
    
    print("\n\n📝 Check audit_log.txt to see all actions logged!")
    print("🔧 Edit policies.json to change what's allowed\n")