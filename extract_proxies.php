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

    private function checkConnectivity(array $proxies): array {
        $results = [];

        foreach (array_chunk($proxies, CONFIG['socket_batch']) as $chunk) {
            $sockets = $map = [];

            foreach ($chunk as $i => $p) {
                $sock = @stream_socket_client(
                    "tcp://{$p['server']}:{$p['port']}",
                    $e, $es, 0,
                    STREAM_CLIENT_ASYNC_CONNECT
                );

                if ($sock) {
                    stream_set_blocking($sock, false);
                    $sockets[$i] = $sock;
                    $map[$i] = ['p' => $p, 't' => microtime(true)];
                } else {
                    $p['status'] = 'Offline';
                    $p['status_rank'] = 0;
                    $results[] = $p;
                }
            }

            $start = microtime(true);
            while ($sockets && microtime(true) - $start < CONFIG['socket_timeout']) {
                $r = $w = $sockets;
                if (stream_select($r, $w, $e, 0, 200000)) {
                    foreach ($w as $id => $s) {
                        fwrite($s, random_bytes(32));
                        $data = fread($s, 1);

                        $p = $map[$id]['p'];
                        $lat = round((microtime(true) - $map[$id]['t']) * 1000);

                        if ($data !== false && $data !== '') {
                            $p['status'] = 'Online';
                            $p['status_rank'] = 2;
                            $p['latency'] = $lat;
                        } else {
                            $p['status'] = 'Unstable';
                            $p['status_rank'] = 1;
                            $p['latency'] = null;
                        }
                        $results[] = $p;
                        fclose($s);
                        unset($sockets[$id]);
                    }
                }
            }

            foreach ($sockets as $id => $s) {
                $p = $map[$id]['p'];
                $p['status'] = 'Offline';
                $p['status_rank'] = 0;
                $results[] = $p;
                fclose($s);
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
