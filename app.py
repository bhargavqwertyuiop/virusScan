
from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import time

app = Flask(__name__)

VIRUSTOTAL_API_KEY = 'YOUR_API_KEY'

# Function to get analysis results using VirusTotal API
def get_analysis_result(analysis_id):
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'attributes' in data['data']:
                return data['data']['attributes']['stats']
            else:
                return f"Unexpected response format: {data}"
        else:
            return f"Error getting analysis result: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error getting analysis result: {str(e)}"

def scan_url(url):
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        params = {
            'url': url
        }
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'id' in data['data']:
                analysis_id = data['data']['id']
                # Wait a bit before requesting analysis results
                time.sleep(15)
                return get_analysis_result(analysis_id)
            else:
                return f"Unexpected response format: {data}"
        else:
            return f"Error scanning URL: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error scanning URL: {str(e)}"

def scan_apk(file):
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        files = {
            'file': file
        }
        response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'id' in data['data']:
                analysis_id = data['data']['id']
                # Wait a bit before requesting analysis results
                time.sleep(60)
                return get_analysis_result(analysis_id)
            else:
                return f"Unexpected response format: {data}"
        else:
            return f"Error scanning file: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error scanning file: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' in request.files:
            apk_file = request.files['file']
            result = scan_apk(apk_file)
        elif 'url' in request.form:
            url = request.form['url']
            result = scan_url(url)
        else:
            return jsonify({'error': 'Invalid request. Please provide either a file or URL.'}), 400
        
        # Ensure result is passed as a dictionary
        if isinstance(result, dict):
            return redirect(url_for('show_result', result=result))
        else:
            return jsonify({'error': 'Failed to scan or retrieve result.'}), 500
    
    except Exception as e:
        return jsonify({'error': f'Error during scanning: {str(e)}'}), 500

@app.route('/result')
def show_result():
    # Retrieve result from query parameters
    result = request.args.get('result')
    
    # Ensure result is parsed correctly as a dictionary
    try:
        result_dict = eval(result) if isinstance(result, str) else result
        if isinstance(result_dict, dict):
            return render_template('result.html', result=result_dict)
        else:
            return jsonify({'error': 'Invalid result format.'}), 400
    except Exception as e:
        return jsonify({'error': f'Error parsing result: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
