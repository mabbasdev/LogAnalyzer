import os
import time

LOG_FILE_PATH = "server_logs.txt"

def analyze_log_properties(file_path):
    """Calculates the file size and estimates token usage for the Gemini API."""
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found.")
        return None

    # Get size metrics
    file_size_bytes = os.path.getsize(file_path)
    file_size_kb = file_size_bytes / 1024
    
    # Estimate tokens: ~1 token per 4 characters/bytes for raw log text
    estimated_tokens = file_size_bytes / 4

    print("--- Log File Metrics ---")
    print(f"📁 Target File: {file_path}")
    print(f"⚖️ Size: {file_size_bytes} Bytes ({file_size_kb:.2f} KB)")
    print(f"🤖 Estimated Gemini Tokens: {int(estimated_tokens)}")
    print(f"🛑 Free Tier Safety: {'SAFE (Under 1,000,000 token limit)' if estimated_tokens < 1000000 else 'WARNING: Exceeds minute limit!'}")
    print("-------------------------\n")
    
    return file_size_bytes

def read_log_contents(file_path):
    """Reads and returns the text contents of the log file."""
    with open(file_path, "r") as file:
        return file.read()

# Run the metrics check
analyze_log_properties(LOG_FILE_PATH)

# Preview the data we will send to the AI
log_data = read_log_contents(LOG_FILE_PATH)
print("📄 Current Log Data Loaded:")
print(log_data)