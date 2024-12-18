<?php
header("Access-Control-Allow-Origin: *");

$url = '';
$error = '';
$harmfulFileTypes = ['exe', 'bat', 'cmd', 'sh', 'scr', 'pif', 'com', 'dll', 'js', 'vbs', 'zip', 'rar', 'tar', 'gz', 'iso'];

if (isset($_GET['url'])) {
    $url = $_GET['url'];

    // Auto-detect HTTP/HTTPS if not provided
    if (!preg_match('/^http(s)?:\/\//', $url)) {
        $url = 'http://' . $url; // Default to HTTP for simplicity
    }

    // Validate the URL
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        $error = "Invalid URL.";
    } else {
        // Initialize cURL session
        $ch = curl_init($url);

        // Set cURL options
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HEADER, false);

        // Execute the request
        $response = curl_exec($ch);

        // Check for errors
        if (curl_errno($ch)) {
            $error = "cURL Error: " . curl_error($ch);
        } else {
            // Close cURL session
            curl_close($ch);

            // Get the content type of the response
            $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            header("Content-Type: " . $contentType);

            // Check if the URL points to a downloadable file
            $pathInfo = pathinfo($url);
            if (isset($pathInfo['extension']) && in_array(strtolower($pathInfo['extension']), $harmfulFileTypes)) {
                echo '<script>
                        var userChoice = confirm("Warning: You are about to download a potentially harmful file. Do you want to continue?");
                        if (!userChoice) {
                            window.history.back();
                        } else {
                            window.location.href = "' . htmlspecialchars($url) . '";
                        }
                      </script>';
                exit;
            }

            // Base URL for links and window opening
            $baseUrl = parse_url($url);
            $proxyBaseUrl = htmlspecialchars($_SERVER['PHP_SELF']) . '?url=';

            // Modify the body to handle all relevant attributes across multiple elements
            $body = preg_replace_callback(
                '/(<(?:link|script|img|iframe|source|object|embed|a|video|audio|form)[^>]*\s(?:src|href|action|data|poster)="?)([^" >]+)"?/i',
                function ($matches) use ($proxyBaseUrl, $baseUrl) {
                    $url = $matches[2];
                    // If the URL is relative, prepend the base URL
                    if (parse_url($url, PHP_URL_SCHEME) === null) {
                        $url = $baseUrl['scheme'] . '://' . $baseUrl['host'] . '/' . ltrim($url, '/');
                    }
                    // Rewrite both absolute and relative URLs to go through the current script
                    return $matches[1] . urlencode($url) . '"';
                },
                $response
            );

            // Handle inline <style> and <script> tags
            $body = preg_replace_callback(
                '/<(style|script)(.*?)>(.*?)<\/\1>/is',
                function ($matches) use ($proxyBaseUrl, $baseUrl) {
                    // Handle inline CSS/JS by rewriting URLs inside them
                    $content = $matches[3];
                    $content = preg_replace_callback(
                        '/url\(["\']?([^"\')]+)["\']?\)/i',
                        function ($urlMatches) use ($proxyBaseUrl, $baseUrl) {
                            $url = $urlMatches[1];
                            if (parse_url($url, PHP_URL_SCHEME) === null) {
                                $url = $baseUrl['scheme'] . '://' . $baseUrl['host'] . '/' . ltrim($url, '/');
                            }
                            return 'url("' . $proxyBaseUrl . urlencode($url) . '")';
                        },
                        $content
                    );
                    return '<' . $matches[1] . $matches[2] . '>' . $content . '</' . $matches[1] . '>';
                },
                $body
            );

            // Handle <form> actions
            $body = preg_replace_callback(
                '/<form[^>]*\saction="([^"]+)"[^>]*>/i',
                function ($matches) use ($proxyBaseUrl, $baseUrl) {
                    $url = $matches[1];
                    if (parse_url($url, PHP_URL_SCHEME) === null) {
                        $url = $baseUrl['scheme'] . '://' . $baseUrl['host'] . '/' . ltrim($url, '/');
                    }
                    return str_replace($matches[1], $proxyBaseUrl . urlencode($url), $matches[0]);
                },
                $body
            );

            // Rewrite window.open calls
            $body = preg_replace_callback(
                '/window\.open\("([^"]+?)"/i',
                function ($matches) use ($proxyBaseUrl) {
                    $url = $matches[1];
                    return 'window.open("' . $proxyBaseUrl . urlencode($url) . '")';
                },
                $body
            );

            // Output the modified response body only
            echo $body;
            exit;
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Le Proxy</title>
</head>
<body>
    <h1>Le Proxy</h1>
    <form method="get" action="">
        <input type="text" name="url" placeholder="Enter URL to visit" value="<?php echo htmlspecialchars($url); ?>" required>
        <input type="submit" value="Open sesame">
    </form>
    <?php if ($error): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
</body>
</html>
