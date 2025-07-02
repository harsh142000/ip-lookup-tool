from flask import Flask, render_template, request, jsonify
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Load your VirusTotal API key from .env file
VT_API_KEY = os.getenv("VT_API_KEY")
print("Loaded API key:", VT_API_KEY)
print("Render API Key:", os.getenv("VT_API_KEY"))


@app.route('/')
def index():
    return render_template('index.html')  # Ensure index.html is in 'templates/' folder

@app.route('/get_ip_info', methods=['POST'])
def get_ip_info():
    data = request.get_json()
    ip_list = data.get('ips', [])

    summary_lines = []
    table_rows = []

    for ip in ip_list:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": VT_API_KEY
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                ip_data = response.json()
                attributes = ip_data.get("data", {}).get("attributes", {})
                isp = attributes.get("as_owner", "N/A")
                country_code = attributes.get("country", "N/A")
                detections = attributes.get("last_analysis_stats", {}).get("malicious", 0)

                # Convert country code to full country name if needed
                country_name = get_full_country_name(country_code)

                summary_lines.append(
                    f"The IP {ip} belongs to the ISP: {isp} from the country: {country_name} with detection count: {detections}."
                )
                table_rows.append(f"<tr><td>{ip}</td><td>{isp}</td><td>{country_name}</td><td>{detections}</td></tr>")
            else:
                summary_lines.append(f"The IP {ip} could not be retrieved (Error {response.status_code}).")
        except Exception as e:
            summary_lines.append(f"The IP {ip} caused an error: {str(e)}")

    return jsonify({
        "summary": "\n\n".join(summary_lines),
        "table": "".join(table_rows)
    })

def get_full_country_name(code):
    from iso3166 import countries
    try:
        return countries.get(code).name
    except:
        return code

if __name__ == '__main__':
    app.run(debug=True)
