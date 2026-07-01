import os
import re
import json
import time
import logging
import random
import smtplib
import threading  # Added for asynchronous execution
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests  # Ensure 'pip install requests' is run in your venv
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
# REAL-WORLD ALERTING GATEWAYS (GMAIL | WHATSAPP)
# ==========================================
def send_email_alert(subject, message_body):
    """Dispatches a secure MIME HTML/Text email notification to the infrastructure team."""
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")
    receiver_email = os.getenv("RECEIVER_EMAIL")

    if not all([smtp_server, smtp_port, sender_email, sender_password, receiver_email]):
        logger.error("[THREAD-EMAIL] Alerting Failure: Email configuration tokens missing from environment.")
        return

    try:
        logger.info(f"[THREAD-EMAIL] Initializing SMTP handshakes with secure server: {smtp_server}...")
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message_body, 'plain'))

        # Secure connection instantiation via TLS
        server = smtplib.SMTP(smtp_server, int(smtp_port))
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        
        logger.info("[THREAD-EMAIL] Email alert dispatched successfully to target routing team.")
    except Exception as email_ex:
        # Crucial Thread Isolation: Catching exceptions explicitly inside the background scope
        logger.error(f"[THREAD-EMAIL] Failed to transmit email notification packet: {str(email_ex)}")

def send_whatsapp_alert(message_body):
    """Dispatches an automated alert payload through a downstream WhatsApp API Gateway."""
    api_url = os.getenv("WHATSAPP_API_URL")
    account_sid = os.getenv("WHATSAPP_ACCOUNT_SID")
    auth_token = os.getenv("WHATSAPP_AUTH_TOKEN")
    from_num = os.getenv("WHATSAPP_FROM_NUMBER")
    to_num = os.getenv("WHATSAPP_TO_NUMBER")

    if not all([api_url, from_num, to_num]):
        logger.error("[THREAD-WHATSAPP] Alerting Failure: WhatsApp routing configurations missing from environment.")
        return

    payload = {
        "From": from_num,
        "To": to_num,
        "Body": message_body
    }

    try:
        logger.info("[THREAD-WHATSAPP] Shipping webhook payload block to remote WhatsApp API Endpoint...")
        
        auth = (account_sid, auth_token) if account_sid and auth_token else None
        response = requests.post(api_url, data=payload, auth=auth, timeout=10)
        
        if response.status_code in [200, 201]:
            logger.info("[THREAD-WHATSAPP] WhatsApp cloud network confirmed message drop success.")
        else:
            logger.error(f"[THREAD-WHATSAPP] WhatsApp API rejected delivery request packet. Status Code: {response.status_code}, Context: {response.text}")
    except Exception as api_ex:
        # Crucial Thread Isolation: Catching exceptions explicitly inside the background scope
        logger.error(f"[THREAD-WHATSAPP] Fatal communication network fault during WhatsApp routing transmission: {str(api_ex)}")

# ==========================================
# COMPLIANCE & ANALYSIS FUNCTIONS
# ==========================================
def local_privacy_anonymizer(raw_text):
    """Scrubs sensitive infrastructure IP nodes locally before transmission."""
    logger.debug("Entering local_privacy_anonymizer function.")
    ip_pattern = r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    
    def replace_ip(match):
        full_match = match.group(1)
        parts = full_match.split('.')
        last_octet = parts[3]
        if len(last_octet) > 3:
            trailing_junk = parts[3][2:]
            return f"[MASKED_IP_NODE]{trailing_junk}"
        return "[MASKED_IP_NODE]"

    return re.sub(ip_pattern, replace_ip, raw_text)

def process_and_analyze_logs(log_text):
    """Cleans raw logs and evaluates vulnerabilities with JSON Schema Enforcement."""
    clean_logs = local_privacy_anonymizer(log_text)
    system_role = (
        "You are an elite Security Operations Center (SOC) Specialist. "
        "Review the log payload and structure violations using the assigned schema constraints."
    )
    
    max_retries = 3
    base_delay = 2
    
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
            if attempt < max_retries - 1:
                delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                logger.warning(f"API dynamic overload encountered ({str(api_error)}). Retrying in {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                logger.error("All scheduled API connection retry attempts exhausted.")
                raise api_error

def execute_alert_router(json_string_output):
    """Parses structured responses and dispatches async non-blocking background alert worker threads."""
    try:
        report_data = json.loads(json_string_output)
        print(f"DEBUG - Raw JSON received: {json_string_output}")
        severity_tier = report_data.get("severity", "INFO").upper()
        is_threat = report_data.get("threat_detected", False)
        
        if is_threat and severity_tier == "CRITICAL":
            logger.warning("CRITICAL ROUTING WARNING: Immediate asynchronous notification pipeline triggered.")
            
            # Construct clear metrics alerts payload text
            alert_subject = "[🚨 CRITICAL SECURITY THREAT] Automated SOC Pipeline Breach Warning"
            alert_body = (
                f"🚨 SYSTEM INCIDENT WARNING ALERT:\n\n"
                f"Reasoning:\n{report_data.get('reasoning')}\n\n"
                f"Remediation Strategy:\n{report_data.get('recommended_action')}\n"
            )
            
            # PERFORMANCE UPGRADE: Spin up background daemon threads to execute network delivery
            # Passing parameters cleanly avoids mutable memory conflicts across shared threads.
            email_thread = threading.Thread(
                target=send_email_alert, 
                args=(alert_subject, alert_body), 
                daemon=True
            )
            whatsapp_thread = threading.Thread(
                target=send_whatsapp_alert, 
                args=(alert_body,), 
                daemon=True
            )
            
            # Start background execution
            email_thread.start()
            whatsapp_thread.start()
            
            logger.info("Alert dispatcher threads spun up successfully. Returning focus to stream tailing.")
        else:
            logger.info(f"Routine operational processing complete. Status level marked: {severity_tier}")
            
    except json.JSONDecodeError as err:
        logger.error(f"Critical structural corruption error occurred: {str(err)}")

# ==========================================
# ENTERPRISE STREAM WATCHDOG ENGINE
# ==========================================
def watch_log_stream(file_path, interval_seconds=10):
    """Passively monitors a live log file while retaining data state on network errors."""
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
                        
                        buffer_pool.clear()
                        last_flush_time = time.time()
                        
                    except Exception as ex:
                        logger.error(f"Pipeline processing interruption: {str(ex)}. Retaining data batch in memory state.")
                        last_flush_time = time.time()
                
                time.sleep(1)

if __name__ == "__main__":
    watch_log_stream(LOG_FILE_PATH, interval_seconds=15)