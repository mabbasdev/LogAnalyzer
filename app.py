import os
import re
from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel, Field

# Load secure environment configurations
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("Error: GEMINI_API_KEY missing from .env file!")

# Initialize the Google GenAI Client
client = genai.Client(api_key=API_KEY)

# ==========================================
# SCHEMA ENFORCEMENT ENGINE
# ==========================================
class ThreatAnalysisReport(BaseModel):
    """Defines a strict enterprise data contract for the AI's analysis output."""
    threat_detected: bool = Field(
        description="True if an operational vulnerability, security risk, or system error exists."
    )
    severity: str = Field(
        description="Strictly classify threat intensity as: INFO, LOW, MEDIUM, or CRITICAL."
    )
    reasoning: str = Field(
        description="A concise summary detailing the core security or operational reason behind this evaluation."
    )
    recommended_action: str = Field(
        description="Actionable remediation step for the infrastructure operations team to resolve the issue."
    )

# ==========================================
# COMPLIANCE & ANALYSIS FUNCTIONS
# ==========================================
def local_privacy_anonymizer(raw_text):
    """Scrubs sensitive infrastructure IP nodes locally before transmission."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.sub(ip_pattern, "[MASKED_IP_NODE]", raw_text)

def process_and_analyze_logs(log_text):
    """Cleans raw logs and evaluates vulnerabilities with JSON Schema Enforcement."""
    # 1. Enforce localized data protection regulations
    clean_logs = local_privacy_anonymizer(log_text)
    
    print("Passing scrubbed batch data to Gemini Security Agent...")
    
    # 2. Define operational guidelines using a specialized system prompt
    system_role = (
        "You are an elite Security Operations Center (SOC) Specialist and Infrastructure Analyst. "
        "Review the provided log stream batch. Extract, categorize, and cross-reference records "
        "to discover security violations, hardware degradation, or performance anomalies."
    )
    
    # 3. Call the modern SDK with type-safe structured constraints
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=f"System Role: {system_role}\n\nAnalyze the following log payload:\n{clean_logs}",
        config={
            'response_mime_type': 'application/json',
            'response_schema': ThreatAnalysisReport, # Enforces strict object blueprint
        }
    )
    
    return response.text

# ==========================================
# RUNTIME PIPELINE EXECUTION
# ==========================================
if __name__ == "__main__":
    # Simulate a critical unauthorized access log vector
    malicious_log_batch = (
        "2026-06-30 14:10:00 INFO Connection initiated from 192.168.10.45\n"
        "2026-06-30 14:10:01 WARNING Access Denied for root user from 192.168.10.45\n"
        "2026-06-30 14:10:02 WARNING Access Denied for root user from 192.168.10.45\n"
        "2026-06-30 14:10:03 WARNING Access Denied for root user from 192.168.10.45\n"
        "2026-06-30 14:10:05 CRITICAL Automated brute-force lockout triggered for node 192.168.10.45"
    )
    
    print("Raw System Log Payload Triggered.")
    # Execute analysis pipeline
    analysis_json_output = process_and_analyze_logs(malicious_log_batch)
    
    print("\nParsed JSON Response from Gemini:")
    print(analysis_json_output)