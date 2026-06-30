import os
import re
import json
import logging
from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel, Field

# Load secure configuration parameters
load_dotenv()

# Setup environmental control flags
IS_DEV = os.getenv("DEVELOPMENT_MODE", "False").upper() == "TRUE"

# Configure native logging visibility based on the runtime environment
if IS_DEV:
    # Development: Expose fine-grained system tracing steps
    logging.basicConfig(level=logging.DEBUG, format="[TRACE] %(message)s")
else:
    # Production: Suppress debugging noise, log only system confirmations or failures
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Validate API configuration status
API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("Critical Error: GEMINI_API_KEY missing from .env file!")

client = genai.Client(api_key=API_KEY)

# ==========================================
# SCHEMA ENFORCEMENT ENGINE
# ==========================================
class ThreatAnalysisReport(BaseModel):
    """Defines a strict enterprise data contract for the AI's analysis output."""
    threat_detected: bool = Field(description="True if a vulnerability or security risk exists.")
    severity: str = Field(description="Classify intensity as: INFO, LOW, MEDIUM, or CRITICAL.")
    reasoning: str = Field(description="Concise operational reason behind this evaluation.")
    recommended_action: str = Field(description="Actionable remediation step for the infrastructure team.")

# ==========================================
# COMPLIANCE & ANALYSIS FUNCTIONS
# ==========================================
def local_privacy_anonymizer(raw_text):
    """Scrubs sensitive infrastructure IP nodes locally before transmission."""
    logger.debug("Entering local_privacy_anonymizer function.")
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    logger.debug(f"Applying regex evaluation pattern: {ip_pattern}")
    anonymized_text = re.sub(ip_pattern, "[MASKED_IP_NODE]", raw_text)
    
    logger.debug("Localized scrubbing layer completed successfully.")
    return anonymized_text

def process_and_analyze_logs(log_text):
    """Cleans raw logs and evaluates vulnerabilities with JSON Schema Enforcement."""
    logger.debug("Beginning process_and_analyze_logs pipeline.")
    
    # Run the compliance engine
    clean_logs = local_privacy_anonymizer(log_text)
    
    logger.debug("Assembling specialized prompt configurations for Gemini Security Agent.")
    system_role = (
        "You are an elite Security Operations Center (SOC) Specialist. "
        "Review the log payload and structure violations using the assigned schema constraints."
    )
    
    logger.info("Dispatching filtered log payload batch to API endpoint...")
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=f"System Role: {system_role}\n\nAnalyze the following log payload:\n{clean_logs}",
        config={
            'response_mime_type': 'application/json',
            'response_schema': ThreatAnalysisReport,
        }
    )
    
    logger.debug("Raw payload stream returned from remote endpoint successfully.")
    return response.text

# ==========================================
# PROACTIVE ROUTING ENGINE
# ==========================================
def execute_alert_router(json_string_output):
    """Parses structural responses and routes actionable operations based on threat tier."""
    logger.debug("Parsing data payload inside execute_alert_router execution frame.")
    try:
        report_data = json.loads(json_string_output)
        severity_tier = report_data.get("severity", "INFO").upper()
        is_threat = report_data.get("threat_detected", False)
        
        logger.debug(f"Target dictionary properties extracted: threat_detected={is_threat}, severity={severity_tier}")
        
        if is_threat and severity_tier == "CRITICAL":
            logger.warning("CRITICAL ROUTING WARNING: Immediate notification pipeline triggered.")
            print(f"\nNotification Alert Filed: {report_data.get('recommended_action')}\n")
        else:
            logger.info(f"Routine operational processing complete. Status level marked: {severity_tier}")
            
    except json.JSONDecodeError as err:
        logger.error(f"Critical structural corruption error occurred: {str(err)}")

# ==========================================
# RUNTIME PIPELINE EXECUTION
# ==========================================
if __name__ == "__main__":
    malicious_log_batch = (
        "2026-06-30 14:10:02 WARNING Access Denied for root user from 192.168.10.45\n"
        "2026-06-30 14:10:05 CRITICAL Automated brute-force lockout triggered for node 192.168.10.45"
    )
    
    logger.info("Initializing system log runtime framework check.")
    analysis_json_output = process_and_analyze_logs(malicious_log_batch)
    execute_alert_router(analysis_json_output)