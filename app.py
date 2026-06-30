import os
import re
from dotenv import load_dotenv
from google import genai

# Load environment variables from the .env file
load_dotenv()

# Verify and retrieve the secure API Key
API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("❌ Critical Error: GEMINI_API_KEY is missing from the .env file!")

# Initialize the modern Google GenAI Client
client = genai.Client(api_key=API_KEY)

def local_privacy_anonymizer(raw_text):
    """
    Scrubs sensitive network infrastructure data locally before transmission.
    Replaces real IPv4 addresses with an anonymous token placeholder.
    """
    # Regex pattern to match standard IPv4 addresses (e.g., 192.168.1.50)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    # Track and replace matching instances
    anonymized_text = re.sub(ip_pattern, "[MASKED_IP_NODE]", raw_text)
    return anonymized_text

def test_ai_connection():
    """Validates the API connection with a rapid, lightweight model test."""
    print("🚀 Initializing connection to Gemini AI Studio...")
    
    # We use the fast, lightweight model for our analysis automation
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents='Respond with exactly one word: Connected.'
    )
    print(f"🤖 API Status Verification: {response.text.strip()}\n")

# --- Execution Test ---
if __name__ == "__main__":
    # 1. Quick test to verify our .env key successfully authenticates
    test_ai_connection()
    
    # 2. Test our local privacy layer
    sample_sensitive_log = "2026-06-30 ERROR: Failed breach attempt detected from unauthorized host IP 10.0.0.158."
    print("🔍 Testing Local Compliance Layer...")
    print(f"❌ Original Log: {sample_sensitive_log}")
    print(f"✅ Scrubbed Log: {local_privacy_anonymizer(sample_sensitive_log)}")