from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('tool.html')

# Route to serve the file_type.html (File Type Selection Page)
@app.route('/file')
def file_type():
    return render_template('file.html')

@app.route('/api/<tool>', methods=['POST'])
def virustotal(tool):
    data = request.json
    resource_type = data['resource_type']
    resource = data['resource']
    api_key = '38847882110b47ed3e730d48c244dbba6ef123e36c5072e2de6efac5f345e93a'  # Replace with your VirusTotal API key

    response = get_report(resource_type, api_key, resource)
    print(response)
    
    if response:
        # Count flagged and clean results
        flagged_count, clean_count = count_results(response)
        formatted_data = {
            'Resource': response.get('resource', 'N/A'),
            'Response Code': response.get('response_code', 'N/A'),
            'Scan Date': response.get('scan_date', 'N/A'),
            'Flagged Count': flagged_count,
            'Clean Count': clean_count
        }
        return jsonify({'status': 'success', 'mydata': [formatted_data]}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Failed to fetch data.'}), 400

def get_report(resource_type, api_key, resource):
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

    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def count_results(response):
    scans = response.get('scans', {})
    flagged_count = 0
    clean_count = 0
    for scan in scans.values():
        if scan.get('detected'):
            flagged_count += 1
        else:
            clean_count += 1
    return flagged_count, clean_count

if __name__ == "__main__":
    app.run(debug=True)
