"""
SOC Log Parsing & Filtering Engine
Author: Cybersecurity SOC Analyst Practice
Description: Production-ready Python script to parse raw web access logs,
             strip ambient static asset noise, audit HTTP error status codes,
             and isolate malicious payloads (SQL Injection & Path Traversal).
"""

import re
from typing import List, Tuple

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS & REGEX PATTERNS
# -----------------------------------------------------------------------------

# Path to the raw Nginx/Apache log file to be analyzed
LOG_FILE: str = "web_access.log"

# Matches HTTP client error (4xx) and server error (5xx) status codes
# \s matches spaces surrounding a 3-digit number starting with 4 or 5
REGEX_STATUS_ERROR: re.Pattern = re.compile(r'\s([45]\d{2})\s')

# Matches SQL Injection (SQLi) keywords and common payload constructs
# re.IGNORECASE ensures case-insensitive matching (e.g., 'union select' vs 'UNION SELECT')
REGEX_SQLI: re.Pattern = re.compile(
    r"(UNION\s+SELECT|OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|INFORMATION_SCHEMA)", 
    re.IGNORECASE
)

# Matches Directory/Path Traversal payload attempts targeting system files
REGEX_PATH_TRAVERSAL: re.Pattern = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)", 
    re.IGNORECASE
)

# Extracts the IPv4 address located at the very beginning of a log line
REGEX_IP: re.Pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# Tuple of file extensions representing low-value static web assets to be filtered out
STATIC_ASSETS: Tuple[str, ...] = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.ico', '.svg', '.woff', '.woff2'
)


# -----------------------------------------------------------------------------
# FILTERING FUNCTIONS
# -----------------------------------------------------------------------------

def load_log_data(file_path: str) -> List[str]:
    """
    Opens and reads the raw log file line by line into a memory list.
    Handles missing file exceptions gracefully to prevent program crash.
    """
    try:
        # Open file in read-only mode using standard UTF-8 encoding
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()  # Returns list of raw log line strings
    except FileNotFoundError:
        # Log error to console if file path does not exist
        print(f"[!] Error: Target log file '{file_path}' was not found.")
        return []  # Return empty list if file reading fails


def strip_static_noise(log_lines: List[str]) -> List[str]:
    """
    Pass 1: Noise Reduction Filter.
    Iterates through log lines and excludes requests for static media/style files.
    """
    clean_lines: List[str] = []
    
    for line in log_lines:
        # Convert line to lowercase to ensure extension check is case-insensitive
        line_lower = line.lower()
        
        # any() checks if ANY static extension string exists anywhere inside line_lower
        # if NOT any(...) means we keep the line only when NO static extension matches
        if not any(ext in line_lower for ext in STATIC_ASSETS):
            clean_lines.append(line)
            
    return clean_lines


def filter_http_errors(log_lines: List[str]) -> List[str]:
    """
    Pass 2: HTTP Status Error Audit.
    Isolates log lines returning 4xx (Client Error) or 5xx (Server Error) status codes.
    """
    error_lines: List[str] = []
    
    for line in log_lines:
        # search() returns a Match object if a 4xx or 5xx status code exists in the line
        if REGEX_STATUS_ERROR.search(line):
            error_lines.append(line.strip())  # strip() removes trailing newline characters
            
    return error_lines


def extract_malicious_vectors(log_lines: List[str]) -> Tuple[List[str], List[str]]:
    """
    Pass 3: Threat Vector Extraction.
    Evaluates log lines against pre-compiled attack signatures for SQLi and Path Traversal.
    """
    sqli_hits: List[str] = []
    traversal_hits: List[str] = []

    for line in log_lines:
        # Test line against SQL Injection regular expression signature
        if REGEX_SQLI.search(line):
            sqli_hits.append(line.strip())
            
        # Test line against Path Traversal regular expression signature
        if REGEX_PATH_TRAVERSAL.search(line):
            traversal_hits.append(line.strip())

    # Return both hit lists as a paired tuple
    return sqli_hits, traversal_hits


def filter_suspicious_ips(log_lines: List[str]) -> List[str]:
    """
    Custom Triage Filter:
    Identifies and returns unique source IPv4 addresses associated with 
    HTTP 403 (Forbidden) or HTTP 500 (Internal Server Error) status responses.
    """
    # Use a set to automatically eliminate duplicate IP addresses
    suspicious_ips = set()

    for line in log_lines:
        # Step 1: Skip static media noise
        if not any(ext in line.lower() for ext in STATIC_ASSETS):
            # Step 2: Check for explicit security/server failure status codes
            if " 403 " in line or " 500 " in line:
                # Step 3: Extract IPv4 address using regex group matching
                match = REGEX_IP.search(line)
                if match:
                    # group(1) extracts the first captured substring (the IP)
                    suspicious_ips.add(match.group(1))

    # Convert unique set to a sorted list for readable reporting
    return sorted(list(suspicious_ips))


# -----------------------------------------------------------------------------
# MAIN PIPELINE EXECUTION
# -----------------------------------------------------------------------------

def run_pipeline() -> None:
    """
    Controls main script execution flow: loads data, runs filter passes,
    and formats triage metrics to stdout.
    """
    # 1. Load data from disk
    raw_logs = load_log_data(LOG_FILE)
    if not raw_logs:
        return  # Exit execution if log file was empty or missing

    print("=" * 60)
    print(" 🛡️ SOC LOG FILTERING & TRIAGE PIPELINE EXECUTION")
    print("=" * 60)

    # 2. Execute filtering passes sequentially
    clean_logs = strip_static_noise(raw_logs)
    error_logs = filter_http_errors(clean_logs)
    sqli_hits, traversal_hits = extract_malicious_vectors(clean_logs)
    suspicious_ips = filter_suspicious_ips(raw_logs)

    # 3. Calculate and display metrics
    total_raw = len(raw_logs)
    total_clean = len(clean_logs)
    stripped_count = total_raw - total_clean

    print(f"[+] Total Raw Log Lines Processed : {total_raw}")
    print(f"[+] Post-Noise Reduction Count     : {total_clean} (Stripped {stripped_count} static requests)")
    print(f"[+] HTTP 4xx/5xx Client/Server Errors: {len(error_logs)}")
    print(f"[+] SQL Injection Signatures Match : {len(sqli_hits)}")
    print(f"[+] Path Traversal Signatures Match: {len(traversal_hits)}")
    print(f"[+] Unique Suspicious IPs (403/500): {len(suspicious_ips)} -> {suspicious_ips}\n")

    # 4. Display sample payload detections for quick inspection
    print("--- 🔍 SAMPLE DETECTED THREATS (FIRST 2 MATCHES) ---")
    for hit in sqli_hits[:2]:
        print(f"  [SQLi DETECTED] {hit}")
    for hit in traversal_hits[:2]:
        print(f"  [TRAVERSAL DETECTED] {hit}")


# Standard Python boilerplate to ensure main pipeline runs only when executed directly
if __name__ == "__main__":
    run_pipeline()