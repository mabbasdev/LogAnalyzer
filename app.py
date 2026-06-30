import os
import re
import json
import time
import logging
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
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.sub(ip_pattern, "[MASKED_IP_NODE]", raw_text)

def process_and_analyze_logs(log_text):
    logger.debug("Beginning processing window evaluation for log batch.")
    clean_logs = local_privacy_anonymizer(log_text)
    
    system_role = (
        "You are an elite Security Operations Center (SOC) Specialist. "
        "Review the log payload and structure violations using the assigned schema constraints."
    )
    
    logger.info("Dispatching live filtered log payload batch to API endpoint...")
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=f"System Role: {system_role}\n\nAnalyze the following log payload:\n{clean_logs}",
        config={
            'response_mime_type': 'application/json',
            'response_schema': ThreatAnalysisReport,
        }
    )
    return response.text

def execute_alert_router(json_string_output):
    try:
        report_data = json.loads(json_string_output)
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
    """
    logger.info(f"Starting Active Watchdog on target file path: {file_path}")
    
    if not os.path.exists(file_path):
        # Establish an empty file placeholder if it doesn't exist yet
        with open(file_path, "w") as f:
            f.write("")
            
    # Seek directly to the end of the existing file to avoid repeating historic logs
    with open(file_path, "r") as file_handle:
        file_handle.seek(0, os.SEEK_END)
        logger.info("Watchdog synced to file stream terminus. Standing by for live inputs...")
        
        buffer_pool = []
        last_flush_time = time.time()
        
        while True:
            current_line = file_handle.readline()
            
            if current_line:
                # Capture new appended data line into the local buffer pool
                if current_line.strip():
                    logger.debug(f"Intercepted new log event line: '{current_line.strip()}'")
                    buffer_pool.append(current_line)
            else:
                # No new text lines found; check if the buffering window has lapsed
                elapsed_time = time.time() - last_flush_time
                
                if buffer_pool and elapsed_time >= interval_seconds:
                    logger.info(f"Sliding interval window lapsed. Compiling {len(buffer_pool)} batched events.")
                    
                    # Combine all lines inside our buffer window into a single payload chunk
                    compiled_payload = "".join(buffer_pool)
                    
                    try:
                        analysis_result = process_and_analyze_logs(compiled_payload)
                        execute_alert_router(analysis_result)
                    except Exception as ex:
                        logger.error(f"Pipeline processing interruption: {str(ex)}")
                    
                    # Clear out the buffer pool and reset timer
                    buffer_pool.clear()
                    last_flush_time = time.time()
                
                # Relieve local processor loop stress
                time.sleep(1)

if __name__ == "__main__":
    # Begin infinite monitoring loop (safely close anytime using Ctrl+C)
    watch_log_stream(LOG_FILE_PATH, interval_seconds=30)