# Fully Documented Python Web Log Filtering & SOC Analysis Engine

A modular, thoroughly commented Python log-parsing pipeline designed for SOC analysts. This engine parses raw Nginx/Apache web access logs, strips ambient static asset noise, audits HTTP status code exceptions, and extracts web application threat vectors (SQL Injection and Path Traversal).

## 📌 Features & Architecture

- **Line-by-Line Code Documentation:** Every function, regex pattern, and conditional loop is commented to document security parsing concepts.
- **Noise Reduction Pass (`strip_static_noise`):** Strips high-frequency static asset requests (`.css`, `.js`, `.png`, `.jpg`, `.ico`, `.svg`) using tuple substring evaluation to optimize pipeline performance.
- **HTTP Error Audit (`filter_http_errors`):** Identifies all `4xx` (Client Error) and `5xx` (Server Error) responses via regular expression matching.
- **Threat Vector Extraction (`extract_malicious_vectors`):** Uses compiled regex objects (`re.compile`) to extract SQL Injection payloads (`UNION SELECT`, `OR '1'='1'`) and Path Traversal signatures (`/etc/passwd`, `../`).
- **Targeted IP Isolation (`filter_suspicious_ips`):** Compiles unique source IPv4 addresses associated with backend failure status codes (`403 Forbidden` and `500 Internal Server Error`).

## 🛠️ Usage Instructions

### Prerequisites
- Python 3.8+ (or Python 3.15+ environment)

### Execution

1. Clone the repository:
   ```bash
   git clone https://github.com/Unknownbsjsb
   cd python-log-filter-engine