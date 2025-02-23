import pandas as pd
import json
import time
from pymongo import MongoClient
import os

# 1️⃣ Connect to MongoDB
client = MongoClient("mongodb+srv://gurleenbatra14:caT3UWUhsicwY3Wo@gurleen.tsoo9.mongodb.net/?tls=true&tlsAllowInvalidCertificates=true&tlsVersion=TLS1_2")
# You can either use the existing database ("Honey") or change it to "records" if desired.
db = client["Honey"]
# Use a single collection called "records" for both auth and session logs.
collection = db["records"]

# 2️⃣ File paths for both types of logs
csv_auth_file = r"C:\Users\svaad\heralding\log_auth.csv"
csv_session_file = r"C:\Users\svaad\heralding\log_session.csv"

# 3️⃣ Loop to upload logs every 2 seconds (1000 iterations removed)
while True:
    print("🔄 Uploading logs...")
    combined_data = []
    
    # Process auth logs
    if os.path.exists(csv_auth_file):
        try:
            auth_df = pd.read_csv(csv_auth_file)
            # Convert DataFrame to a list of dicts
            auth_data = json.loads(auth_df.to_json(orient="records"))
            # Tag each record as 'auth'
            for record in auth_data:
                record["log_type"] = "auth"
            combined_data.extend(auth_data)
            print("✅ Auth logs processed.")
        except Exception as e:
            print(f"Error processing auth logs: {e}")
    else:
        print("Auth CSV file not found.")
    
    # Process session logs
    if os.path.exists(csv_session_file):
        try:
            session_df = pd.read_csv(csv_session_file)
            session_data = json.loads(session_df.to_json(orient="records"))
            # Tag each record as 'session'
            for record in session_data:
                record["log_type"] = "session"
            combined_data.extend(session_data)
            print("✅ Session logs processed.")
        except Exception as e:
            print(f"Error processing session logs: {e}")
    else:
        print("Session CSV file not found.")
    
    # Upload combined logs to the single collection
    if combined_data:
        try:
            collection.insert_many(combined_data)
            print("✅ Combined logs uploaded successfully!")
        except Exception as e:
            print(f"Error uploading combined logs: {e}")
    else:
        print("No logs to upload.")
    
    time.sleep(2)  # Wait 2 seconds before the next upload
