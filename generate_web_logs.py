import random
from datetime import datetime, timedelta

# Attack patterns embedded in noise
ips = ["192.168.1.45", "10.0.0.12", "172.16.0.88", "185.220.101.5", "45.33.32.156"]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "sqlmap/1.6.0#stable (http://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

clean_paths = ["/index.html", "/about.html", "/login.php", "/static/css/main.css", "/api/v1/health"]
attack_paths = [
    "/login.php?user=admin' OR '1'='1",
    "/products.php?id=1 UNION SELECT username, password FROM users--",
    "/../../../../etc/passwd",
    "/admin/config.php",
    "/.env"
]

start_time = datetime.now() - timedelta(hours=4)

with open("web_access.log", "w") as f:
    for i in range(1250):
        timestamp = (start_time + timedelta(seconds=i*11)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        # Inject occasional attacks
        if random.random() < 0.12:
            ip = random.choice(["185.220.101.5", "45.33.32.156"])
            path = random.choice(attack_paths)
            agent = random.choice(user_agents[1:]) # Automated scanner agents
            status = random.choice([200, 403, 500])
        else:
            ip = random.choice(ips[:3])
            path = random.choice(clean_paths)
            agent = user_agents[0]
            status = 200

        f.write(f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} 2326 "-" "{agent}"\n')

print("Successfully generated web_access.log with 1,250 log entries.")