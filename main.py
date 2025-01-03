from flask import Flask, request, jsonify, make_response
import requests

app = Flask(__name__)

@app.route('/')
def home():
    with open('index.html') as f:
        return f.read()

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    if not url:
        return "No URL provided", 400
    
    # Basic URL validation to avoid open redirects
    if not (url.startswith("http://") or url.startswith("https://")):
        return "Invalid URL. Please use a valid http or https URL.", 400

    # Try to fetch the URL content
    try:
        response = requests.get(url, timeout=10)
        
        # Create a response with CORS headers
        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }
        
        # Create a new response object
        proxy_response = make_response(response.content)
        proxy_response.headers.update(cors_headers)
        proxy_response.headers['Content-Type'] = response.headers.get('Content-Type', 'text/html')
        
        return proxy_response

    except requests.Timeout:
        return "Request timed out. The URL may be unreachable.", 504
    except requests.RequestException as e:
        return f"An error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
