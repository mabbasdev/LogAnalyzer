import os
import re
import json
import time
import logging
import random
from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel, Field

# Load secure configuration parameters
load_dotenv()

IS_DEV = os.getenv("DEVELOPMENT_MODE", "False").upper() == "TRUE"

if IS_DEV:
    logging.basicConfig(level=logging.DEBUG, format="[TRACE] %(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("Critical Error: GEMINI_API_KEY missing from .env file!")

client = genai.Client(api_key=API_KEY)
LOG_FILE_PATH = "server_logs.txt"

# ==========================================
# SCHEMA ENFORCEMENT ENGINE
# ==========================================
class ThreatAnalysisReport(BaseModel):
    threat_detected: bool = Field(description="True if a vulnerability or security risk exists.")
    severity: str = Field(description="Classify intensity as: INFO, LOW, MEDIUM, or CRITICAL.")
    reasoning: str = Field(description="Concise operational reason behind this evaluation.")
    recommended_action: str = Field(description="Actionable remediation step for the infrastructure team.")

# ==========================================
# COMPLIANCE & ANALYSIS FUNCTIONS
# ==========================================
def local_privacy_anonymizer(raw_text):
    """
    Scrubs sensitive infrastructure IP nodes locally before transmission.
    Enhanced to handle concatenated text anomalies where IPs run directly 
    into trailing timestamps or alphanumeric strings without boundaries.
    """
    logger.debug("Entering local_privacy_anonymizer function.")
    
    ip_pattern = r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    logger.debug(f"Applying robust regex evaluation pattern: {ip_pattern}")
    
    def replace_ip(match):
        full_match = match.group(1)
        parts = full_match.split('.')
        last_octet = parts[3]
        
        if len(last_octet) > 3:
            # Reconstruct trailing concatenated data lines cleanly
            trailing_junk = parts[3][2:]
            return f"[MASKED_IP_NODE]{trailing_junk}"
        
        return "[MASKED_IP_NODE]"

    anonymized_text = re.sub(ip_pattern, replace_ip, raw_text)
    logger.debug("Localized scrubbing layer completed successfully.")
    return anonymized_text

def process_and_analyze_logs(log_text):
    """Cleans raw logs and evaluates vulnerabilities with JSON Schema Enforcement."""
    logger.debug("Beginning processing window evaluation for log batch.")
    
    # Cleanse the incoming text through our compliance engine
    clean_logs = local_privacy_anonymizer(log_text)
    
    system_role = (
        "You are an elite Security Operations Center (SOC) Specialist. "
        "Review the log payload and structure violations using the assigned schema constraints."
    )
    
    max_retries = 3
    base_delay = 2  # Start with a 2-second delay
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Dispatching live filtered log payload batch to API endpoint (Attempt {attempt + 1}/{max_retries})...")
            
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=f"System Role: {system_role}\n\nAnalyze the following log payload:\n{clean_logs}",
                config={
                    'response_mime_type': 'application/json',
                    'response_schema': ThreatAnalysisReport,
                }
            )
            return response.text
            
        except Exception as api_error:
            # Check if we have retries left
            if attempt < max_retries - 1:
                # Calculate backoff delay: base_delay * (2 ^ attempt) + a tiny bit of random noise (jitter)
                delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                logger.warning(f"API dynamic overload encountered ({str(api_error)}). Retrying in {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                # Exhausted all attempts; re-raise the exception to be logged by the main pipeline loop
                logger.error("All scheduled API connection retry attempts exhausted.")
                raise api_error

def execute_alert_router(json_string_output):
    """Parses structured responses and routes actionable operations based on threat tier."""
    try:
        report_data = json.loads(json_string_output)
        print(f"DEBUG - Raw JSON received: {json_string_output}")
        severity_tier = report_data.get("severity", "INFO").upper()
        is_threat = report_data.get("threat_detected", False)
        
        if is_threat and severity_tier == "CRITICAL":
            logger.warning("CRITICAL ROUTING WARNING: Immediate notification pipeline triggered.")
            print(f"\n[ALERT DISPATCH] Remediation Strategy: {report_data.get('recommended_action')}\n")
        else:
            logger.info(f"Routine operational processing complete. Status level marked: {severity_tier}")
            
    except json.JSONDecodeError as err:
        logger.error(f"Critical structural corruption error occurred: {str(err)}")

# ==========================================
# ENTERPRISE STREAM WATCHDOG ENGINE
# ==========================================
def watch_log_stream(file_path, interval_seconds=10):
    """
    Passively monitors a live log file. Accumulates incoming records over a 
    sliding interval window before batching requests to control API quotas.
    Retains buffer pool states in memory if the downstream analysis engine fails.
    """
    logger.info(f"Starting Active Watchdog on target file path: {file_path}")
    
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            f.write("")
            
    with open(file_path, "r") as file_handle:
        file_handle.seek(0, os.SEEK_END)
        logger.info("Watchdog synced to file stream terminus. Standing by for live inputs...")
        
        buffer_pool = []
        last_flush_time = time.time()
        
        while True:
            current_line = file_handle.readline()
            
            if current_line:
                if current_line.strip():
                    logger.debug(f"Intercepted new log event line: '{current_line.strip()}'")
                    buffer_pool.append(current_line)
            else:
                elapsed_time = time.time() - last_flush_time
                
                if buffer_pool and elapsed_time >= interval_seconds:
                    logger.info(f"Sliding interval window lapsed. Compiling {len(buffer_pool)} batched events.")
                    compiled_payload = "".join(buffer_pool)
                    
                    try:
                        analysis_result = process_and_analyze_logs(compiled_payload)
                        execute_alert_router(analysis_result)
                        
                        # SUCCESS TRACE: Only clear memory and advance time window if transaction completes
                        buffer_pool.clear()
                        last_flush_time = time.time()
                        
                    except Exception as ex:
                        # OUTAGE RECOVERY TRACE: Retain current logs in RAM buffer pool.
                        # Move the window timestamp forward to calculate the next processing interval check.
                        logger.error(f"Pipeline processing interruption: {str(ex)}. Retaining data batch in memory state.")
                        last_flush_time = time.time()
                
                time.sleep(1)

if __name__ == "__main__":
    watch_log_stream(LOG_FILE_PATH, interval_seconds=15)

# Testing the Script for The "Malformed Text Bomb" Test (Regex Stress)