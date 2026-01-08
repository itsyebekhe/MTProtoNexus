<?php
declare(strict_types=1);

/**
 * Telegram Proxy Scanner - v2025.1 (Fix: Invalid Secret)
 */

const CONFIG = [
    'input_file'      => 'usernames.json',
    'output_json'     => 'extracted_proxies.json',
    'output_html'     => 'index.html',
    'cache_duration'  => 3600,
    'socket_timeout'  => 2,
    'batch_size'      => 50,
    'socket_batch'    => 20
];

class ProxyScanner {
    private array $userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    ];

    public function run(): array {
        echo "Starting Scan...\n";
        $usernames = $this->loadUsernames();
        if (empty($usernames)) return [];

        $rawHtml = $this->fetchChannels($usernames);
        $proxies = $this->extractProxies($rawHtml);
        
        echo "Found " . count($proxies) . " raw proxies. Checking connectivity...\n";
        $checkedProxies = $this->checkConnectivity($proxies);
        
        // Smart Sort: Online > Latency
        usort($checkedProxies, function ($a, $b) {
            if ($a['status'] === 'Online' && $b['status'] !== 'Online') return -1;
            if ($a['status'] !== 'Online' && $b['status'] === 'Online') return 1;
            return ($a['latency'] ?? 9999) <=> ($b['latency'] ?? 9999);
        });

        file_put_contents(CONFIG['output_json'], json_encode($checkedProxies, JSON_PRETTY_PRINT));
        return $checkedProxies;
    }

    private function loadUsernames(): array {
        if (!file_exists(CONFIG['input_file'])) return [];
        $data = json_decode(file_get_contents(CONFIG['input_file']), true);
        return is_array($data) ? $data : [];
    }

    private function fetchChannels(array $usernames): array {
        $mh = curl_multi_init();
        $handles = [];
        $results = [];

        foreach ($usernames as $user) {
            $url = 'https://t.me/s/' . trim($user);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_USERAGENT      => $this->userAgents[array_rand($this->userAgents)],
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_ENCODING       => '' // Handle gzip
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$user] = $ch;
        }

        $active = null;
        do {
            $status = curl_multi_exec($mh, $active);
            if ($active) curl_multi_select($mh);
        } while ($active && $status == CURLM_OK);

        foreach ($handles as $user => $ch) {
            $results[] = curl_multi_getcontent($ch);
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        return $results;
    }

    private function extractProxies(array $htmlContents): array {
        $found = [];
        // Regex looks for the whole tg:// link
        $linkRegex = '/proxy\?(?=[^"]*server=)(?=[^"]*port=)([^"\'\s<>]+)/i';

        foreach ($htmlContents as $html) {
            // Decode HTML entities first (&amp; -> &)
            $cleanHtml = html_entity_decode($html);

            if (preg_match_all($linkRegex, $cleanHtml, $matches)) {
                foreach ($matches[1] as $queryString) {
                    // Manual Parameter Extraction (More robust than parse_str)
                    $server = $this->getParam($queryString, 'server');
                    $port   = $this->getParam($queryString, 'port');
                    $secret = $this->getParam($queryString, 'secret');

                    if ($server && $port && $secret) {
                        // Strict Secret Cleaning
                        $secret = $this->cleanSecret($secret);
                        if (!$secret) continue; // Skip if secret became invalid

                        $key = "$server:$port";
                        
                        // Detect Type
                        $type = match (true) {
    str_starts_with($secret, 'dd') => 'MTProto Secure',
    str_starts_with($secret, 'ee') => 'MTProto TLS',
    default => 'MTProto'
};

                        $found[$key] = [
                            'server' => $server,
                            'port'   => (int)$port,
                            'secret' => $secret,
                            'type'   => $type,
                            // Rebuild URL cleanly to ensure validity
                            'tg_url' => "tg://proxy?server={$server}&port={$port}&secret={$secret}"
                        ];
                    }
                }
            }
        }
        return array_values($found);
    }

    /**
     * Extracts a parameter value using regex to avoid parsing issues
     */
    private function getParam(string $query, string $name): ?string {
        if (preg_match('/(?:^|&)' . $name . '=([^&]+)/', $query, $matches)) {
            return trim(urldecode($matches[1]));
        }
        return null;
    }

    /**
     * Validates and cleans the secret
     */
    private function cleanSecret(string $secret): ?string {
    $secret = strtolower(trim($secret));

    if (!ctype_xdigit($secret)) {
        return null;
    }

    $len = strlen($secret);

    // Basic MTProto rules
    if (str_starts_with($secret, 'dd') && $len !== 32) return null; // 16 bytes
    if (str_starts_with($secret, 'ee') && $len < 34) return null;  // TLS
    if (!str_starts_with($secret, 'dd') && !str_starts_with($secret, 'ee') && $len !== 32) {
        return null;
    }

    return $secret;
}

    private function checkConnectivity(array $proxies): array
{
    $results = [];

    $batchSize = CONFIG['batch_size'] ?? 20;
    $timeout   = CONFIG['socket_timeout'] ?? 2;

    $chunks = array_chunk($proxies, (int)$batchSize);

    foreach ($chunks as $chunk) {
        $sockets = [];
        $map     = [];

        foreach ($chunk as $idx => $proxy) {
            $address = "tcp://{$proxy['server']}:{$proxy['port']}";

            $socket = @stream_socket_client(
                $address,
                $errno,
                $errstr,
                0,
                STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT
            );

            if ($socket !== false) {
                stream_set_blocking($socket, false);
                $sockets[$idx] = $socket;
                $map[$idx] = [
                    'proxy' => $proxy,
                    'start' => microtime(true),
                ];
            } else {
                $proxy['status']  = 'Offline';
                $proxy['latency'] = null;
                $results[] = $proxy;
            }
        }

        $startWait = microtime(true);

        while (!empty($sockets) && (microtime(true) - $startWait) < $timeout) {

            $write  = $sockets; // we only care about write-ready sockets
            $read   = null;
            $except = null;

            $changed = @stream_select($read, $write, $except, 0, 200000);

            if ($changed === false) {
                break;
            }

            if ($changed > 0) {
                foreach ($write as $id => $sock) {
                    $info = $map[$id];

                    $latency = (int) round(
                        (microtime(true) - $info['start']) * 1000
                    );

                    $p = $info['proxy'];

                    // Optional: minimal data write to detect dead accepts
                    @fwrite($sock, random_bytes(32));
                    stream_set_timeout($sock, 0, 200000);
                    $data = @fread($sock, 1);

                    if ($data !== false) {
                        $p['status'] = 'Online';
                    } else {
                        $p['status'] = 'Unstable';
                    }

                    $p['latency'] = $latency;

                    $results[] = $p;

                    fclose($sock);
                    unset($sockets[$id], $map[$id]);
                }
            }
        }

        // Anything still pending = Offline
        foreach ($sockets as $id => $sock) {
            $p = $map[$id]['proxy'];
            $p['status']  = 'Offline';
            $p['latency'] = null;
            $results[] = $p;
            fclose($sock);
        }
    }

    return $results;
}
}

// --- Run ---
$isCli = (php_sapi_name() === 'cli');
$shouldScan = false;
$lastScanTime = file_exists(CONFIG['output_json']) ? filemtime(CONFIG['output_json']) : 0;

if ($isCli || !file_exists(CONFIG['output_json']) || (time() - $lastScanTime) > CONFIG['cache_duration'] || isset($_GET['scan'])) {
    $shouldScan = true;
}

if ($shouldScan) {
    $scanner = new ProxyScanner();
    $proxies = $scanner->run();
    $lastScanTime = time();
} else {
    $proxies = json_decode(file_get_contents(CONFIG['output_json']), true);
}

// Prepare View Data
$onlineCount = count(array_filter($proxies, fn($p) => $p['status'] === 'Online'));
$totalCount = count($proxies);
$scanTimestamp = $lastScanTime;

// Render
ob_start();
require 'template.phtml';
$htmlContent = ob_get_clean();
file_put_contents(CONFIG['output_html'], $htmlContent);

if ($isCli) echo "Generated index.html with " . $onlineCount . " online proxies.\n";
else echo $htmlContent;
?>
