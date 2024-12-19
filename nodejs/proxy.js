const http = require('http');
const fs = require('fs');
const path = require('path');
const { createProxyServer } = require('http-proxy');

const proxy = createProxyServer({});
const PORT = 3000;

const server = http.createServer((req, res) => {
    if (req.url === '/') {
        // Serve the HTML file
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else {
        // Proxy other requests
        const targetUrl = req.url.startsWith('http') ? req.url : `http://${req.url}`;
        proxy.web(req, res, { target: targetUrl, changeOrigin: true }, (err) => {
            console.error('Proxy error:', err);
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end('Bad Gateway');
        });
    }
});

server.listen(PORT, () => {
    console.log(`Proxy server is running on http://localhost:${PORT}`);
});
