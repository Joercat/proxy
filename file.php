<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
set_time_limit(0);
ini_set('memory_limit', '-1');

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: *");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class ProxyServer {
    private $url;
    private $harmfulFileTypes = ['exe', 'bat', 'cmd', 'sh', 'scr', 'pif', 'com', 'dll', 'js', 'vbs', 'zip', 'rar', 'tar', 'gz', 'iso'];
    private $cookieJar;
    private $userAgent;

    public function __construct() {
        $this->cookieJar = tempnam(sys_get_temp_dir(), 'cookie_');
        $this->userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
    }

    public function handleRequest() {
        if (!isset($_GET['url'])) {
            return null; // No URL provided, will show form
        }

        $this->url = $this->normalizeUrl($_GET['url']);
        
        if (!filter_var($this->url, FILTER_VALIDATE_URL)) {
            throw new Exception("Invalid URL provided.");
        }

        if ($this->isDownloadableFile()) {
            return $this->handleFileDownload();
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return $this->handlePostRequest();
        }

        return $this->fetchAndModifyContent();
    }

    private function normalizeUrl($url) {
        if (!preg_match('/^http(s)?:\/\//i', $url)) {
            $url = 'http://' . $url;
        }
        return $url;
    }

    private function isDownloadableFile() {
        $pathInfo = pathinfo($this->url);
        return isset($pathInfo['extension']) && in_array(strtolower($pathInfo['extension']), $this->harmfulFileTypes);
    }

    private function handleFileDownload() {
        $ch = $this->createCurlHandle();
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_exec($ch);
        
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $contentLength = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
        
        header("Content-Type: $contentType");
        header("Content-Length: $contentLength");
        header('Content-Disposition: attachment; filename="' . basename($this->url) . '"');
        
        curl_setopt($ch, CURLOPT_NOBODY, false);
        curl_exec($ch);
        curl_close($ch);
        exit;
    }

    private function handlePostRequest() {
        $ch = $this->createCurlHandle();
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $_POST);
        return $this->executeRequest($ch);
    }

    private function createCurlHandle() {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_COOKIEFILE => $this->cookieJar,
            CURLOPT_COOKIEJAR => $this->cookieJar,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_ENCODING => '',
            CURLOPT_TIMEOUT => 60,
            CURLOPT_HEADER => true
        ]);

        $headers = getallheaders();
        $curlHeaders = [];
        foreach ($headers as $key => $value) {
            if (!in_array(strtolower($key), ['host', 'content-length'])) {
                $curlHeaders[] = "$key: $value";
            }
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);

        return $ch;
    }

    private function fetchAndModifyContent() {
        $ch = $this->createCurlHandle();
        return $this->executeRequest($ch);
    }

    private function executeRequest($ch) {
        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            throw new Exception(curl_error($ch));
        }

        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        
        $this->forwardHeaders($headers);
        
        curl_close($ch);

        return $this->modifyContent($body);
    }

    private function forwardHeaders($headers) {
        foreach (explode("\n", $headers) as $header) {
            if (preg_match('/^(?!Transfer-Encoding|Content-Length|Connection|Cookie|Set-Cookie)/i', $header)) {
                header(trim($header));
            }
        }
    }

    private function modifyContent($content) {
        $baseUrl = parse_url($this->url);
        $proxyUrl = $_SERVER['PHP_SELF'] . '?url=';

        $content = preg_replace_callback(
            '/(<[^>]+(?:src|href|action|data|poster)=[\'"])([^\'"]+)([\'"])/i',
            function($matches) use ($baseUrl, $proxyUrl) {
                $url = $this->resolveUrl($matches[2], $baseUrl);
                return $matches[1] . $proxyUrl . urlencode($url) . $matches[3];
            },
            $content
        );

        $content = preg_replace_callback(
            '/url\([\'"]?([^\'")]+)[\'"]?\)/i',
            function($matches) use ($baseUrl, $proxyUrl) {
                $url = $this->resolveUrl($matches[1], $baseUrl);
                return 'url("' . $proxyUrl . urlencode($url) . '")';
            },
            $content
        );

        $content = preg_replace_callback(
            '/window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]/i',
            function($matches) use ($proxyUrl) {
                return 'window.location.href="' . $proxyUrl . urlencode($matches[1]) . '"';
            },
            $content
        );

        return $content;
    }

    private function resolveUrl($url, $baseUrl) {
        if (parse_url($url, PHP_URL_SCHEME) === null) {
            if (strpos($url, '//') === 0) {
                return $baseUrl['scheme'] . ':' . $url;
            }
            if (strpos($url, '/') === 0) {
                return $baseUrl['scheme'] . '://' . $baseUrl['host'] . $url;
            }
            return $baseUrl['scheme'] . '://' . $baseUrl['host'] . '/' . ltrim($url, '/');
        }
        return $url;
    }
}

try {
    $proxy = new ProxyServer();
    $content = $proxy->handleRequest();
    if ($content !== null) {
        echo $content;
    }
} catch (Exception $e) {
    header('HTTP/1.1 500 Internal Server Error');
    $errorMessage = "Error: " . htmlspecialchars($e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Le Proxy</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        .form-container { text-align: center; }
        input[type="text"] { width: 80%; padding: 0.5rem; margin: 1rem 0; }
        input[type="submit"] { padding: 0.5rem 1rem; background: #007bff; color: white; border: none; cursor: pointer; }
        .error { color: red; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="form-container">
        <h1>Le Proxy</h1>
        <form method="get" action="">
            <input type="text" name="url" placeholder="Enter URL to visit (e.g., example.com)" required>
            <input type="submit" value="Open Sesame">
        </form>
        <?php if (isset($errorMessage)): ?>
            <div class="error"><?php echo $errorMessage; ?></div>
        <?php endif; ?>
    </div>
</body>
</html>
