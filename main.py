from flask import Flask, request, make_response, send_from_directory
import requests

app = Flask(__name__)

@app.route('/')
def home():
    # Serve the HTML file
    return send_from_directory('.', 'index.html')

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    
    # Check if the URL parameter is provided
    if not url:
        return make_response("No URL provided", 400)
    
    # Basic URL validation to ensure it's a valid http or https URL
    if not (url.startswith("http://") or url.startswith("https://")):
        return make_response("Invalid URL. Please use a valid http or https URL.", 400)

    # Attempt to fetch the URL content
    try:
        response = requests.get(url, timeout=10)

        # Create a response with CORS headers
        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }
        
        # Create a new response object and set the necessary headers
        proxy_response = make_response(response.content)
        proxy_response.headers.update(cors_headers)
        proxy_response.headers['Content-Type'] = response.headers.get('Content-Type', 'text/html')

        return proxy_response

    except requests.Timeout:
        return make_response("Request timed out. The URL may be unreachable.", 504)
    except requests.RequestException as e:
        return make_response(f"An error occurred: {str(e)}", 500)

if __name__ == '__main__':
    app.run(debug=True)
