from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Main page route
@app.route('/')
def index():
    return render_template('tool.html')

# Route for file type selection
@app.route('/file')
def file_type():
    return render_template('file.html')

# Route to handle VirusTotal API requests
@app.route('/scan', methods=['POST'])
def scan():
    data = request.form
    resource_type = data.get('resource_type')
    resource = data.get('resource')
    api_key = '38847882110b47ed3e730d48c244dbba6ef123e36c5072e2de6efac5f345e93a'  # Replace with your VirusTotal API key

    if not resource_type or not resource:
        return render_template('result.html', result="Missing resource type or resource.")

    response = get_report(resource_type, api_key, resource)

    if response:
        formatted_data = format_response(response, resource_type)
        return render_template('result.html', result=formatted_data)
    else:
        return render_template('result.html', result="Failed to fetch data.")

def get_report(resource_type, api_key, resource):
    """
    Fetches the VirusTotal report based on resource type.
    """
    if resource_type == 'file':
        url = "https://www.virustotal.com/vtapi/v2/file/report"
    elif resource_type == 'url':
        url = "https://www.virustotal.com/vtapi/v2/url/report"
    elif resource_type == 'ip':
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    else:
        return None

    params = {'apikey': api_key, 'resource': resource}
    if resource_type == 'ip':
        params = {'apikey': api_key, 'ip': resource}

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def format_response(response, resource_type):
    """
    Parses and formats the response from VirusTotal API.
    """
    if resource_type == 'file':
        positives = response.get('positives', 'N/A')
        total = response.get('total', 'N/A')
        scan_result = f'{positives}/{total} scans flagged this file as malicious.'

    elif resource_type == 'url':
        positives = response.get('positives', 'N/A')
        total = response.get('total', 'N/A')
        scan_result = f'{positives}/{total} scans flagged this URL as malicious.'

    elif resource_type == 'ip':
        positives = response.get('positives', 'N/A')  # Adjust based on the actual API response
        scan_result = f'{positives} detections for IP address.'

    else:
        scan_result = "Unsupported resource type."

    return scan_result

if __name__ == "__main__":
    app.run(debug=True)
