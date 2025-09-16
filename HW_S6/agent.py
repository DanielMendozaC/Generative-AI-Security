#!/usr/bin/env python3
"""
Simplified MCP Sanitizer Agent
Demonstrates Model Context Protocol architecture with sanitization tools
"""

import json
import re
import hashlib
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

# =============================================================================
# MCP TOOL DEFINITIONS
# =============================================================================

@dataclass
class ToolResult:
    """Result from executing a tool"""
    success: bool
    content: str
    metadata: Dict[str, Any] = None

class MCPTool(ABC):
    """Abstract base class for MCP tools"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        pass
    
    @abstractmethod
    def execute(self, text: str) -> ToolResult:
        pass

class PIIAnonymizerTool(MCPTool):
    """Tool for anonymizing Personal Identifiable Information"""
    
    @property
    def name(self) -> str:
        return "anonymize_pii"
    
    @property
    def description(self) -> str:
        return "Anonymizes names, emails, phone numbers, addresses, and other PII"
    
    def execute(self, text: str) -> ToolResult:
        sanitized = text
        
        # Anonymize emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        sanitized = re.sub(email_pattern, '[EMAIL_REDACTED]', sanitized)
        
        # Anonymize phone numbers
        phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
        sanitized = re.sub(phone_pattern, '[PHONE_REDACTED]', sanitized)
        
        # Anonymize common names (simple approach)
        common_names = ['John', 'Jane', 'Smith', 'Johnson', 'Williams', 'Brown', 'Jones']
        for name in common_names:
            sanitized = re.sub(rf'\b{name}\b', '[NAME_REDACTED]', sanitized, flags=re.IGNORECASE)
        
        # Anonymize addresses (simple pattern)
        address_pattern = r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln)\b'
        sanitized = re.sub(address_pattern, '[ADDRESS_REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return ToolResult(
            success=True,
            content=sanitized,
            metadata={"tool_used": self.name, "redactions_made": text != sanitized}
        )

class FinancialRedactorTool(MCPTool):
    """Tool for redacting financial information"""
    
    @property
    def name(self) -> str:
        return "redact_financial"
    
    @property
    def description(self) -> str:
        return "Redacts credit card numbers, IBAN, bank accounts, and other financial data"
    
    def execute(self, text: str) -> ToolResult:
        sanitized = text
        
        # Redact credit card numbers (simple pattern)
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        sanitized = re.sub(cc_pattern, '[CREDIT_CARD_REDACTED]', sanitized)
        
        # Redact potential IBAN numbers
        iban_pattern = r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b'
        sanitized = re.sub(iban_pattern, '[IBAN_REDACTED]', sanitized)
        
        # Redact potential account numbers (8-17 digits)
        account_pattern = r'\b\d{8,17}\b'
        sanitized = re.sub(account_pattern, '[ACCOUNT_REDACTED]', sanitized)
        
        # Redact SSN pattern
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        sanitized = re.sub(ssn_pattern, '[SSN_REDACTED]', sanitized)
        
        return ToolResult(
            success=True,
            content=sanitized,
            metadata={"tool_used": self.name, "redactions_made": text != sanitized}
        )

class DataMaskingTool(MCPTool):
    """Tool for general data masking and anonymization"""
    
    @property
    def name(self) -> str:
        return "mask_data"
    
    @property
    def description(self) -> str:
        return "General data masking for sensitive identifiers and numbers"
    
    def execute(self, text: str) -> ToolResult:
        sanitized = text
        
        # Mask potential ID numbers
        id_pattern = r'\b[A-Z]{2,3}\d{6,12}\b'
        sanitized = re.sub(id_pattern, '[ID_REDACTED]', sanitized)
        
        # Mask dates that might be DOB
        date_pattern = r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'
        sanitized = re.sub(date_pattern, '[DATE_REDACTED]', sanitized)
        
        # Mask potential license plates
        license_pattern = r'\b[A-Z]{1,3}\d{1,4}[A-Z]{0,3}\b'
        sanitized = re.sub(license_pattern, '[LICENSE_REDACTED]', sanitized)
        
        return ToolResult(
            success=True,
            content=sanitized,
            metadata={"tool_used": self.name, "redactions_made": text != sanitized}
        )

# =============================================================================
# MCP SERVER
# =============================================================================

class MCPServer:
    """Simplified MCP Server that manages tools"""
    
    def __init__(self):
        self.tools: Dict[str, MCPTool] = {}
        self._register_default_tools()
    
    def _register_default_tools(self):
        """Register the default sanitization tools"""
        tools = [
            PIIAnonymizerTool(),
            FinancialRedactorTool(),
            DataMaskingTool()
        ]
        
        for tool in tools:
            self.tools[tool.name] = tool
    
    def list_tools(self) -> List[Dict[str, str]]:
        """List all available tools"""
        return [
            {"name": tool.name, "description": tool.description}
            for tool in self.tools.values()
        ]
    
    def execute_tool(self, tool_name: str, text: str) -> ToolResult:
        """Execute a specific tool"""
        if tool_name not in self.tools:
            return ToolResult(
                success=False,
                content=f"Tool '{tool_name}' not found",
                metadata={"error": "tool_not_found"}
            )
        
        try:
            return self.tools[tool_name].execute(text)
        except Exception as e:
            return ToolResult(
                success=False,
                content=f"Error executing tool: {str(e)}",
                metadata={"error": "execution_failed"}
            )

# =============================================================================
# MCP CLIENT / AI AGENT
# =============================================================================

class SanitizerAgent:
    """Main agent that uses MCP server to sanitize text"""
    
    def __init__(self, mcp_server: MCPServer):
        self.mcp_server = mcp_server
    
    def _select_tool(self, text: str, user_intent: str) -> str:
        """
        Simple AI tool selection based on intent and text analysis
        In a real implementation, this would use an LLM like Gemini
        """
        text_lower = text.lower()
        intent_lower = user_intent.lower()
        
        # Priority scoring for each tool
        scores = {
            "anonymize_pii": 0,
            "redact_financial": 0,
            "mask_data": 0
        }
        
        # Check for PII indicators
        pii_keywords = ['email', 'name', 'phone', 'address', 'personal']
        if any(keyword in intent_lower for keyword in pii_keywords):
            scores["anonymize_pii"] += 3
        
        if '@' in text or 'phone' in text_lower or any(name in text for name in ['John', 'Jane', 'Smith']):
            scores["anonymize_pii"] += 2
        
        # Check for financial indicators
        financial_keywords = ['credit', 'card', 'bank', 'account', 'financial', 'payment', 'iban']
        if any(keyword in intent_lower for keyword in financial_keywords):
            scores["redact_financial"] += 3
        
        if re.search(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}', text):
            scores["redact_financial"] += 2
        
        # Check for general masking needs
        masking_keywords = ['mask', 'hide', 'general', 'identifier']
        if any(keyword in intent_lower for keyword in masking_keywords):
            scores["mask_data"] += 2
        
        # Return tool with highest score
        return max(scores.items(), key=lambda x: x[1])[0]
    
    def sanitize_text(self, text: str, user_intent: str) -> Dict[str, Any]:
        """
        Main method to sanitize text based on user intent
        """
        print("🔍 Analyzing text and user intent...")
        
        # Get available tools
        available_tools = self.mcp_server.list_tools()
        print(f"📋 Available tools: {[tool['name'] for tool in available_tools]}")
        
        # Select appropriate tool
        selected_tool = self._select_tool(text, user_intent)
        print(f"🎯 Selected tool: {selected_tool}")
        
        # Execute the tool
        print(f"⚙️ Executing {selected_tool}...")
        result = self.mcp_server.execute_tool(selected_tool, text)
        
        if result.success:
            print("✅ Sanitization completed successfully!")
        else:
            print(f"❌ Sanitization failed: {result.content}")
        
        return {
            "original_text": text,
            "sanitized_text": result.content,
            "tool_used": selected_tool,
            "success": result.success,
            "metadata": result.metadata
        }

# =============================================================================
# DEMO / MAIN APPLICATION
# =============================================================================

def demo_sanitizer():
    """Demonstration of the MCP Sanitizer Agent"""
    
    print("🛡️ MCP Sanitizer Agent Demo")
    print("=" * 50)
    
    # Initialize MCP Server and Agent
    server = MCPServer()
    agent = SanitizerAgent(server)
    
    # Sample test data
    test_cases = [
        {
            "text": "Hi, I'm John Smith. My email is john.smith@example.com and my phone is 555-123-4567. I live at 123 Main Street.",
            "intent": "anonymize personal information"
        },
        {
            "text": "Please process payment with credit card 4532-1234-5678-9012 or use bank account 987654321.",
            "intent": "redact financial data"
        },
        {
            "text": "Driver license ABC123456, born 12/15/1985, SSN 123-45-6789.",
            "intent": "mask sensitive identifiers"
        }
    ]
    
    for i, case in enumerate(test_cases, 1):
        print(f"\n🧪 Test Case {i}")
        print(f"Intent: {case['intent']}")
        print(f"Original: {case['text']}")
        print("-" * 30)
        
        result = agent.sanitize_text(case['text'], case['intent'])
        
        print(f"Sanitized: {result['sanitized_text']}")
        print(f"Tool used: {result['tool_used']}")
        print(f"Success: {result['success']}")
        print("=" * 50)

def interactive_mode():
    """Interactive mode for testing"""
    
    print("🛡️ MCP Sanitizer Agent - Interactive Mode")
    print("Enter text to sanitize, or 'quit' to exit")
    print("=" * 50)
    
    server = MCPServer()
    agent = SanitizerAgent(server)
    
    while True:
        print("\nAvailable tools:")
        for tool in server.list_tools():
            print(f"  - {tool['name']}: {tool['description']}")
        
        text = input("\n📝 Enter text to sanitize: ").strip()
        if text.lower() in ['quit', 'exit', 'q']:
            break
        
        intent = input("🎯 Describe what you want to sanitize (e.g., 'remove PII'): ").strip()
        
        if text and intent:
            print("\n" + "-" * 30)
            result = agent.sanitize_text(text, intent)
            print(f"\n📋 Results:")
            print(f"  Original: {result['original_text']}")
            print(f"  Sanitized: {result['sanitized_text']}")
            print(f"  Tool: {result['tool_used']}")
            print("-" * 30)
        else:
            print("❌ Please provide both text and intent")

if __name__ == "__main__":
    print("Choose mode:")
    print("1. Demo mode (predefined examples)")
    print("2. Interactive mode")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        demo_sanitizer()
    elif choice == "2":
        interactive_mode()
    else:
        print("Running demo mode by default...")
        demo_sanitizer()