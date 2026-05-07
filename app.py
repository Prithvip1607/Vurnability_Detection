from flask import Flask, jsonify, send_from_directory
import json
import os

app = Flask(__name__, static_folder='static')

DATA_PATH = os.path.join(os.path.dirname(__file__), 'dataset', 'final_structured_dataset.json')

def load_data():
    with open(DATA_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/vulnerabilities')
def get_all():
    data = load_data()
    return jsonify(data)

@app.route('/api/zero-days')
def get_zero_days():
    data = load_data()
    results = [
        d for d in data if
        d.get('attack_type') == 'zero-day' or
        'zero-day' in d.get('text', '').lower() or
        '0-day' in d.get('text', '').lower() or
        '0day' in d.get('text', '').lower()
    ]
    return jsonify(results)

@app.route('/api/stats')
def get_stats():
    data = load_data()
    zero_days = [
        d for d in data if
        d.get('attack_type') == 'zero-day' or
        'zero-day' in d.get('text', '').lower() or
        '0-day' in d.get('text', '').lower()
    ]

    severity = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    vuln_types = {}
    targets = {}

    for d in zero_days:
        label = d.get('label', 'LOW')
        severity[label] = severity.get(label, 0) + 1

        vt = d.get('vulnerability_type') or 'Unknown'
        vuln_types[vt] = vuln_types.get(vt, 0) + 1

        ts = d.get('target_software') or 'Unknown'
        targets[ts] = targets.get(ts, 0) + 1

    return jsonify({
        'total': len(data),
        'zero_days': len(zero_days),
        'severity': severity,
        'vulnerability_types': vuln_types,
        'targets': targets
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
