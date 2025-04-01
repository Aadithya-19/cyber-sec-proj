from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import pandas as pd
import time
import threading
from flask_mail import Mail, Message
import logging
import csv
import os
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import openai
from response_engine import ResponseEngine

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
mail = Mail(app)

# Logging setup (ensure it's defined globally)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure OpenAI API key
openai.api_key = os.environ.get('OPENAI_API_KEY', '')  

# CSV paths
log_auth_csv = r"C:\Users\svaad\OneDrive\Documents\csv-files\log_session.csv"  # Fixed: Use log_auth_csv, not log_auth
log_sessions_csv = r"C:\Users\svaad\OneDrive\Documents\csv-files\log_session.csv"
malicious_attempts_csv = "malicious_attempts.csv"

# Initialize ResponseEngine
response_engine = ResponseEngine()

# Attack Detector
class AttackDetector:
    def __init__(self):
        self.model = RandomForestClassifier()
        X_train = np.array([[1, 0, 0], [0, 1, 1], [1, 1, 0]])
        y_train = np.array([0, 1, 0])
        self.model.fit(X_train, y_train)

    def predict_attack(self, log_data):
        features = self._extract_features(log_data)
        prediction = self.model.predict([features])[0]
        return "Potential attack detected: Suspicious activity identified" if prediction == 1 else "No attack detected."

    def _extract_features(self, log_data):
        return [1, 0, 0]

attack_detector = AttackDetector()

# ... (other routes like /, /logs, /malicious_attempts, /analyze_attacks, /send_email remain the same)
@app.route('/malicious_attempts')
def get_malicious_attempts():
    try:
        with open(malicious_attempts_csv, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            entries = list(reader)
        return jsonify(entries)
    except Exception as e:
        logger.error(f"Error reading malicious attempts CSV: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('log_update', {'data': 'Initial data from server'})

def check_for_log_updates():
    last_check_time = time.time()
    while True:
        try:
            current_time = time.time()
            if current_time - last_check_time > 10:  # Keep or adjust interval
                # Fixed: Use log_auth_csv, not log_auth.csv
                auth_data = pd.read_csv(log_auth_csv).to_dict(orient='records')
                session_data = pd.read_csv(log_sessions_csv).to_dict(orient='records')
                
                logger.info(f"Sending update: {len(auth_data)} auth logs, {len(session_data)} session logs")
                socketio.emit('log_update', {'auth_logs': auth_data})
                socketio.emit('session_update', {'session_logs': session_data})

                # Analyze attacks using ResponseEngine
                combined_logs = auth_data + session_data
                attack_results = {}
                for log in combined_logs:
                    attack_type = 'suspicious'  # Default; refine with your logic
                    confidence = 0.6  # Example; refine with your logic
                    context = {
                        'ip': log.get('ip', 'Unknown'),
                        'location': log.get('location', 'Unknown')
                    }
                    actions = response_engine.determine_response(attack_type, confidence, context)
                    attack_results[log.get('id', 'unknown')] = {
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'actions': actions,
                        'context': context
                    }

                # Log to CSV if actions aren't just ['alert']
                for log_id, details in attack_results.items():
                    if details['actions'] != ['alert']:
                        response_engine._log_response(details['attack_type'], details['confidence'], details['actions'], details['context'])

                # Enhance attack description with OpenAI, with fallback
                attack_summary = ", ".join([f"{k}: {v['attack_type']} (Confidence: {v['confidence']}, Actions: {v['actions']})" for k, v in attack_results.items()])
                malicious_attempts = []
                try:
                    with open(malicious_attempts_csv, newline='') as csvfile:
                        reader = csv.DictReader(csvfile)
                        malicious_attempts = list(reader)
                except FileNotFoundError:
                    logger.warning(f"Malicious attempts CSV not found at {malicious_attempts_csv}")
                
                prompt = f"Enhance this security alert with detailed, user-friendly language: {attack_summary}. Include data from malicious attempts: {malicious_attempts}. Include potential actions the user should take and a sense of urgency if applicable."
                try:
                    response = openai.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=150
                    )
                    enhanced_description = response.choices[0].message.content.strip()
                except (openai.RateLimitError, openai.APIError) as e:
                    logger.error(f"OpenAI error generating description: {str(e)}")
                    enhanced_description = "No attack detected yet. Check logs for updates or wait for ML analysis."

                socketio.emit('attack_description', {'description': enhanced_description})

                last_check_time = current_time
        except Exception as e:
            # Fixed: Use the globally defined logger
            logger.error(f"Error reading files or generating description: {str(e)}")
        time.sleep(5)  # Keep or adjust sleep interval

threading.Thread(target=check_for_log_updates, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

# ... (rest of your app.py, including other routes and main execution)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)