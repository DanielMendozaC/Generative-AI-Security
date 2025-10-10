import streamlit as st
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from anthropic import Anthropic
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Page config
st.set_page_config(
    page_title="Zero Trust AI Agent Demo v2",
    page_icon="🛡️",
    layout="wide"
)

# ======================
# GLOBAL STATE FOR RATE LIMITING
# ======================
if 'request_history' not in st.session_state:
    st.session_state.request_history = defaultdict(list)

# ======================
# FEATURE 1: RATE LIMITING
# ======================
def check_rate_limit(function_name, max_requests=5, window_seconds=60):
    """Block if too many requests in time window"""
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)
    
    # Remove old requests
    st.session_state.request_history[function_name] = [
        ts for ts in st.session_state.request_history[function_name] 
        if ts > cutoff
    ]
    
    # Check current count
    current_count = len(st.session_state.request_history[function_name])
    
    # Check if exceeded
    if current_count >= max_requests:
        return False, f"🚫 Rate limit exceeded: {current_count}/{max_requests} requests in {window_seconds}s", current_count
    
    # Record this request
    st.session_state.request_history[function_name].append(now)
    return True, f"✅ Rate limit OK: {current_count + 1}/{max_requests} requests used", current_count + 1

# ======================
# FEATURE 2: INPUT VALIDATION
# ======================
def validate_filename(filename):
    """Prevent path traversal and injection attacks"""
    dangerous_patterns = [
        ('../', 'Path traversal attempt'),
        ('~/', 'Home directory access'),
        ('/etc/', 'System file access'),
        ('/root/', 'Root directory access'),
        ('passwd', 'Password file access'),
        (';', 'Command injection'),
        ('|', 'Pipe command'),
        ('&', 'Command chaining'),
        ('`', 'Command substitution'),
        ('$', 'Variable expansion')
    ]
    
    filename_lower = filename.lower()
    
    for pattern, reason in dangerous_patterns:
        if pattern in filename_lower:
            return False, f"🚨 BLOCKED: {reason} detected ('{pattern}')"
    
    return True, "✅ Filename validated"

# ======================
# FEATURE 3: RISK SCORING
# ======================
def calculate_risk_score(function_name, filename):
    """Calculate 0-100 risk score with detailed breakdown"""
    score = 0
    reasons = []
    
    # Function risk levels
    risk_levels = {
        'delete_file': 40,
        'write_file': 20,
        'read_file': 10
    }
    func_risk = risk_levels.get(function_name, 0)
    score += func_risk
    reasons.append(f"Function risk ({function_name}): +{func_risk}")
    
    # File sensitivity detection
    sensitive_keywords = ['credential', 'password', 'secret', 'key', 'token', 'api', 'private', 'confidential']
    if any(keyword in filename.lower() for keyword in sensitive_keywords):
        score += 40
        reasons.append("Sensitive file detected: +40")
    
    # Time-based risk (after hours = suspicious)
    current_hour = datetime.now().hour
    if current_hour < 6 or current_hour > 22:
        score += 30
        reasons.append(f"After-hours access ({current_hour}:00): +30")
    
    # Determine risk level
    if score >= 70:
        risk_level = "🔴 HIGH"
        risk_color = "red"
    elif score >= 40:
        risk_level = "🟡 MEDIUM"
        risk_color = "orange"
    else:
        risk_level = "🟢 LOW"
        risk_color = "green"
    
    return score, reasons, risk_level, risk_color

# ======================
# ORIGINAL ZERO TRUST FUNCTIONS
# ======================
def load_policies():
    with open("policies.json", "r") as f:
        return json.load(f)

def check_permission(function_name):
    policies = load_policies()
    is_allowed = policies.get(function_name, {}).get("allowed", False)
    
    # LOG EVERYTHING (Enhanced logging)
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "function": function_name,
        "decision": "ALLOWED" if is_allowed else "BLOCKED",
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
    """Enhanced execution with all security checks"""
    filename = arguments.get("filename", "")
    
    # SECURITY CHECK 1: Input Validation
    valid, validation_msg = validate_filename(filename)
    if not valid:
        return validation_msg, "BLOCKED_VALIDATION", None
    
    # SECURITY CHECK 2: Rate Limiting
    rate_ok, rate_msg, request_count = check_rate_limit(function_name)
    if not rate_ok:
        return rate_msg, "BLOCKED_RATE_LIMIT", request_count
    
    # SECURITY CHECK 3: Policy Check
    if not check_permission(function_name):
        return f"❌ BLOCKED: {function_name} not allowed by policy", "BLOCKED_POLICY", request_count
    
    # Execute if all checks pass
    if function_name == "read_file":
        result = read_file(arguments["filename"])
    elif function_name == "write_file":
        result = write_file(arguments["filename"], arguments["content"])
    elif function_name == "delete_file":
        result = delete_file(arguments["filename"])
    else:
        result = "Unknown function"
    
    return result, "ALLOWED", request_count

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
    
    # Extract Claude's text responses
    claude_thoughts = []
    for block in response.content:
        if block.type == "text":
            claude_thoughts.append(block.text)
    
    if response.stop_reason == "tool_use":
        tool_use = next(block for block in response.content if block.type == "tool_use")
        claude_text = " ".join(claude_thoughts) if claude_thoughts else "Claude is calling a function..."
        return tool_use.name, tool_use.input, claude_text
    else:
        claude_text = claude_thoughts[0] if claude_thoughts else "No response"
        return None, None, claude_text

# ======================
# STREAMLIT UI
# ======================

# Title with version badge
st.title("🛡️ Zero Trust AI Agent Demo")
st.caption("v2.0 - Enhanced with Rate Limiting, Input Validation & Risk Scoring")
st.markdown("---")

# Create test file if doesn't exist
if not os.path.exists("test.txt"):
    with open("test.txt", "w") as f:
        f.write("CONFIDENTIAL CUSTOMER DATABASE\nCustomer ID: CUST-2024-1847\nName: Sarah Johnson")

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
            
            # Show Claude's thinking
            if claude_text:
                st.markdown("### 💭 Claude's Response")
                st.info(claude_text)
            
            if function_name:
                filename = arguments.get("filename", "unknown")
                
                st.markdown("### 🔧 Function Call")
                st.success(f"🤖 Claude wants to call: **{function_name}**")
                st.json(arguments)
                
                # NEW: Risk Score Display
                st.markdown("### ⚠️ Risk Assessment")
                risk_score, risk_reasons, risk_level, risk_color = calculate_risk_score(function_name, filename)
                
                risk_col1, risk_col2 = st.columns([1, 2])
                with risk_col1:
                    st.metric("Risk Score", f"{risk_score}/100", risk_level)
                with risk_col2:
                    st.progress(risk_score / 100)
                    for reason in risk_reasons:
                        st.caption(reason)
                
                # Step 2: Enhanced Security Checks
                st.markdown("### 🔍 Zero Trust Security Checks")
                
                check_col1, check_col2, check_col3, check_col4 = st.columns(4)
                
                with check_col1:
                    st.info("**Input Validation**")
                    valid, msg = validate_filename(filename)
                    if valid:
                        st.success("✅ Clean")
                    else:
                        st.error("❌ Blocked")
                
                with check_col2:
                    st.info("**Rate Limit**")
                    rate_ok, rate_msg, count = check_rate_limit(function_name, max_requests=5)
                    if rate_ok:
                        st.success(f"✅ {count}/5")
                    else:
                        st.error("❌ Exceeded")
                
                with check_col3:
                    st.info("**Policy Check**")
                    policies = load_policies()
                    is_allowed = policies.get(function_name, {}).get("allowed", False)
                    if is_allowed:
                        st.success("✅ Allowed")
                    else:
                        st.error("❌ Denied")
                
                with check_col4:
                    st.info("**Audit Log**")
                    st.success("📝 Logged")
                
                # Step 3: Execute (or block)
                st.markdown("### 📊 Result")
                result, status, request_count = execute_function(function_name, arguments)
                
                if status == "ALLOWED":
                    st.success(result)
                elif status == "BLOCKED_VALIDATION":
                    st.error(f"🚨 INPUT VALIDATION FAILED\n\n{result}")
                elif status == "BLOCKED_RATE_LIMIT":
                    st.error(f"🚫 RATE LIMIT EXCEEDED\n\n{result}")
                elif status == "BLOCKED_POLICY":
                    st.error(f"❌ POLICY VIOLATION\n\n{result}")
            else:
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
    
    st.markdown("---")
    
    # # NEW: Rate Limit Status
    # st.subheader("🚦 Rate Limits")
    # for func in ['read_file', 'write_file', 'delete_file']:
    #     count = len(st.session_state.request_history.get(func, []))
    #     st.progress(count / 5, text=f"{func}: {count}/5")
    
    # st.markdown("---")
    
    # NEW: Security Features
    st.subheader("🛡️ Security Features")
    st.success("✅ Input Validation")
    st.success("✅ Rate Limiting")
    st.success("✅ Risk Scoring")
    st.success("✅ Policy Engine")
    st.success("✅ Audit Logging")

# Footer
st.markdown("---")
st.caption("🛡️ Zero Trust AI Agent v2 | Enhanced Security Features")