import streamlit as st
import json
import os
from datetime import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Page config
st.set_page_config(
    page_title="Zero Trust AI Agent Demo",
    page_icon="🛡️",
    layout="wide"
)

# ======================
# ZERO TRUST FUNCTIONS
# ======================
def load_policies():
    with open("policies.json", "r") as f:
        return json.load(f)

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

def read_file(filename):
    try:
        with open(filename, "r") as f:
            content = f.read()
        return f"✅ File content: {content}"
    except Exception as e:
        return f"❌ Error: {e}"

def write_file(filename, content):
    try:
        with open(filename, "w") as f:
            f.write(content)
        return f"✅ Successfully wrote to {filename}"
    except Exception as e:
        return f"❌ Error: {e}"

def delete_file(filename):
    try:
        os.remove(filename)
        return f"✅ Successfully deleted {filename}"
    except Exception as e:
        return f"❌ Error: {e}"

def execute_function(function_name, arguments):
    if not check_permission(function_name):
        return f"❌ BLOCKED: {function_name} not allowed by policy", "BLOCKED"
    
    if function_name == "read_file":
        result = read_file(arguments["filename"])
    elif function_name == "write_file":
        result = write_file(arguments["filename"], arguments["content"])
    elif function_name == "delete_file":
        result = delete_file(arguments["filename"])
    else:
        result = "Unknown function"
    
    return result, "ALLOWED"

# Define tools for Claude
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

def run_agent(user_request):
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        tools=tools,
        messages=[{"role": "user", "content": user_request}]
    )
    
    # Extract Claude's text responses (what Claude says)
    claude_thoughts = []
    for block in response.content:
        if block.type == "text":
            claude_thoughts.append(block.text)
    
    if response.stop_reason == "tool_use":
        tool_use = next(block for block in response.content if block.type == "tool_use")
        claude_text = " ".join(claude_thoughts) if claude_thoughts else "Claude is calling a function..."
        return tool_use.name, tool_use.input, claude_text
    else:
        # Claude responded without using tools
        claude_text = claude_thoughts[0] if claude_thoughts else "No response"
        return None, None, claude_text

# ======================
# STREAMLIT UI
# ======================

# Title
st.title("🛡️ Zero Trust AI Agent Demo")
st.markdown("---")

# Create test file if doesn't exist
if not os.path.exists("test.txt"):
    with open("test.txt", "w") as f:
        f.write("This is sensitive test data")

# Layout: 2 columns
col1, col2 = st.columns([2, 1])

with col1:
    st.header("💬 AI Agent Interface")
    
    # Custom input
    user_input = st.text_area(
        "Enter your request:",
        value=st.session_state.get('user_input', ''),
        height=150,
        placeholder="Example: Read the file test.txt"
    )
    
    run_button = st.button("🚀 Run Agent", type="primary", use_container_width=True)
    
    if run_button and user_input:
        with st.spinner("🤖 Claude is thinking..."):
            # Step 1: Claude decides what to do
            function_name, arguments, claude_text = run_agent(user_input)
            
            # Show Claude's thinking/response
            if claude_text:
                st.markdown("### 💭 Claude's Response")
                st.info(claude_text)
            
            if function_name:
                st.markdown("### 🔧 Function Call")
                st.success(f"🤖 Claude wants to call: **{function_name}**")
                st.json(arguments)
                
                # Step 2: Show security check
                st.markdown("### 🔍 Zero Trust Security Check")
                
                policies = load_policies()
                is_allowed = policies.get(function_name, {}).get("allowed", False)
                
                check_col1, check_col2, check_col3 = st.columns(3)
                
                with check_col1:
                    st.info("**Step 1: Policy Check**")
                    if is_allowed:
                        st.success("✅ Policy: ALLOWED")
                    else:
                        st.error("❌ Policy: BLOCKED")
                
                with check_col2:
                    st.info("**Step 2: Audit Log**")
                    st.success("📝 Logged to audit_log.txt")
                
                with check_col3:
                    st.info("**Step 3: Decision**")
                    if is_allowed:
                        st.success("✅ EXECUTE")
                    else:
                        st.error("❌ BLOCK")
                
                # Step 3: Execute (or block)
                st.markdown("### 📊 Result")
                result, status = execute_function(function_name, arguments)
                
                if status == "ALLOWED":
                    st.success(result)
                else:
                    st.error(result)
            else:
                # Claude didn't use a tool, just responded with text
                st.markdown("### 💬 Claude's Response")
                st.info(claude_text)

with col2:
    st.header("🔧 System Status")
    
    # Show current policies
    st.subheader("📋 Current Policies")
    policies = load_policies()
    for func, policy in policies.items():
        status = "✅" if policy.get("allowed") else "❌"
        st.text(f"{status} {func}")

# Footer
st.markdown("---")
st.caption("🛡️ Zero Trust AI Agent Demo | Built with Streamlit + Claude + Python")