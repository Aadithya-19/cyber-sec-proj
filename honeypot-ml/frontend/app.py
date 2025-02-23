from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import pandas as pd
import time
import threading
from flask_mail import Mail, Message
import logging
from sklearn.ensemble import RandomForestClassifier  # Example ML model
import numpy as np
import os
import openai

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure Flask-Mail for email sending (update with your SMTP settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Example: Gmail SMTP
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email (sender)
app.config['MAIL_PASSWORD'] = 'your-app-password'  # Use an App Password for Gmail (sender)
mail = Mail(app)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure OpenAI API key (use environment variable in production)
openai.api_key = os.environ.get('OPENAI_API_KEY', 'api-key-here')

# Update these paths to where your CSV files are located
log_auth_csv = "/app/csv/log_auth.csv"
log_sessions_csv = "/app/csv/log_session.csv"

# Simple ML model for attack detection (example)
class AttackDetector:
    def __init__(self):
        # Example: Train a Random Forest classifier on dummy data
        self.model = RandomForestClassifier()
        # Dummy training data (replace with your actual log data features)
        X_train = np.array([[1, 0, 0], [0, 1, 1], [1, 1, 0]])  # Example features
        y_train = np.array([0, 1, 0])  # 0 = Normal, 1 = Attack
        self.model.fit(X_train, y_train)

    def predict_attack(self, log_data):
        # Convert log data to features (simplified example)
        features = self._extract_features(log_data)
        prediction = self.model.predict([features])[0]
        return "Potential attack detected: Suspicious activity identified" if prediction == 1 else "No attack detected."

    def _extract_features(self, log_data):
        # Implement feature extraction from log data (e.g., count failed logins, session duration)
        # This is a placeholder—replace with your actual feature extraction logic
        return [1, 0, 0]  # Dummy features

attack_detector = AttackDetector()

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/generate_help', methods=['POST'])
def generate_help():
    try:
        data = request.get_json()
        context = data.get('context', 'No context provided')
        
        prompt = f"Generate concise, user-friendly help text for a log monitoring dashboard based on this context: '{context}'. Keep it professional, clear, and actionable."
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100
        )
        help_text = response.choices[0].message.content.strip()
        
        return jsonify({'help_text': help_text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logs')
def get_logs():
    try:
        auth_data = pd.read_csv(log_auth_csv).to_dict(orient='records')
        session_data = pd.read_csv(log_sessions_csv).to_dict(orient='records')
        return jsonify({
            'auth_logs': auth_data,
            'session_logs': session_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/send_email', methods=['POST'])
def send_email():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({"message": "No email provided"}), 400

        prompt = f"Generate a professional, concise email notification for a log monitoring system. Include details about potential security events based on the following: logs show {len(pd.read_csv(log_auth_csv))} authentication attempts and {len(pd.read_csv(log_sessions_csv))} sessions, with a potential attack described as: {attack_detector.predict_attack(pd.read_csv(log_auth_csv).to_dict(orient='records') + pd.read_csv(log_sessions_csv).to_dict(orient='records'))}. Address the user politely and provide a link to review logs at http://localhost:5000/logs."
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        email_content = response.choices[0].message.content.strip()

        msg = Message('Log Monitoring Alert', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = email_content
        mail.send(msg)
        return jsonify({"message": "Email sent successfully!"})
    except Exception as e:
        return jsonify({"message": f"Error sending email: {str(e)}"}), 500

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('log_update', {'data': 'Initial data from server'})

def check_for_log_updates():
    last_check_time = time.time()
    while True:
        try:
            current_time = time.time()
            if current_time - last_check_time > 5:
                auth_data = pd.read_csv(log_auth_csv).to_dict(orient='records')
                session_data = pd.read_csv(log_sessions_csv).to_dict(orient='records')
                
                logger.info(f"Sending update: {len(auth_data)} auth logs, {len(session_data)} session logs")
                socketio.emit('log_update', {'auth_logs': auth_data})
                socketio.emit('session_update', {'session_logs': session_data})

                combined_logs = auth_data + session_data
                base_description = attack_detector.predict_attack(combined_logs)
                prompt = f"Enhance this security alert with detailed, user-friendly language: {base_description}. Include potential actions the user should take and a sense of urgency if applicable."
                response = openai.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=150
                )
                enhanced_description = response.choices[0].message.content.strip()
                socketio.emit('attack_description', {'description': enhanced_description})

                last_check_time = current_time
        except Exception as e:
            logger.error(f"Error reading files or generating description: {e}")
        time.sleep(5)
# Start the background thread for log checking
threading.Thread(target=check_for_log_updates, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)