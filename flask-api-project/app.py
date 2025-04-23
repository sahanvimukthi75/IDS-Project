from prometheus_client import Counter, generate_latest, REGISTRY
from prometheus_client import start_http_server
from collections import Counter as LabelCounter
import joblib
import pandas as pd
from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

# Start Prometheus metrics server
start_http_server(9090)

# Prometheus metrics
prediction_counter = Counter('flask_predictions_total', 'Total predictions made')
success_counter = Counter('flask_success_total', 'Successful predictions')
error_counter = Counter('flask_errors_total', 'Total errors')
label_prediction_counter = Counter(
    'flask_prediction_label_total',
    'Total predictions per label',
    ['label']
)

# Load model and label encoder
model = joblib.load("attack_detection_model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Define required features
REQUIRED_FEATURES = [
    'Src Port', 'Dst Port', 'Protocol', 'Flow Duration',
    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Pkt Len Mean',
    'Flow Byts/s', 'Flow Pkts/s', 'SYN Flag Cnt',
    'Init Fwd Win Byts', 'ACK Flag Cnt', 'RST Flag Cnt'
]

# Preload known labels in Prometheus
KNOWN_LABELS = list(label_encoder.classes_)
for label in KNOWN_LABELS:
    label_prediction_counter.labels(label=label).inc(0)

# 📧 Email alert function
def send_email_alert(attack_labels):
    sender_email = "dkviyanage358@gmail.com"         # Your Gmail (sender)
    receiver_email = "dkviyanage358@gmail.com"       # Recipient Gmail
    app_password = "svwbsobrtgjidicz "    # Your 16-char App Password (no spaces)

    subject = "🚨 Intrusion Alert!"
    body = f"⚠️ Suspicious activity detected!\n\nAttack types: {', '.join(set(attack_labels))}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print("✅ Alert email sent.")
    except Exception as e:
        print("❌ Failed to send email:", e)

@app.route('/')
def index():
    return "🚀 Intrusion Detection API is up!"

@app.route('/metrics')
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

@app.route('/predict', methods=['POST'])
def predict():
    prediction_counter.inc()

    try:
        if 'file' not in request.files:
            error_counter.inc()
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        df = pd.read_csv(file)

        # Check for missing features
        missing = [feat for feat in REQUIRED_FEATURES if feat not in df.columns]
        if missing:
            error_counter.inc()
            return jsonify({'error': f'Missing features: {missing}'}), 400

        input_data = df[REQUIRED_FEATURES]
        preds = model.predict(input_data)
        decoded_labels = label_encoder.inverse_transform(preds)

        # Prometheus label count
        label_counts = LabelCounter(decoded_labels)
        for label, count in label_counts.items():
            label_prediction_counter.labels(label=label).inc(count)

        success_counter.inc()

        # 🚨 Filter and alert only for attack labels
        attack_labels = [label for label in decoded_labels if label in ['DoS', 'Web Attack', 'Brute Force', 'U2R']]
        if attack_labels:
            send_email_alert(attack_labels)

        # Build JSON response
        results = [
            {'prediction': int(pred), 'label': label}
            for pred, label in zip(preds, decoded_labels)
        ]

        return jsonify({'results': results, 'status': 'success'})

    except Exception as e:
        error_counter.inc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
