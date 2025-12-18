<?php
declare(strict_types=1);

/**
 * Telegram Proxy Scanner - v2025
 * Features: Static Gen, Secret Detection, Smart Sorting
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
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ];

    public function run(): array {
        echo "Starting Scan...\n";
        $usernames = $this->loadUsernames();
        if (empty($usernames)) return [];

        $rawHtml = $this->fetchChannels($usernames);
        $proxies = $this->extractProxies($rawHtml);
        
        echo "Checking " . count($proxies) . " proxies...\n";
        $checkedProxies = $this->checkConnectivity($proxies);
        
        // Smart Sort: Online > Latency > Secret Type
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
                CURLOPT_SSL_VERIFYPEER => false
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
        $regex = '/(?:https?:\/\/t\.me\/proxy\?|tg:\/\/proxy\?)([^"\'\s<>]+)/i';

        foreach ($htmlContents as $html) {
            if (preg_match_all($regex, $html, $matches)) {
                foreach ($matches[0] as $fullUrl) {
                    $parsed = parse_url($fullUrl);
                    if (!isset($parsed['query'])) continue;
                    parse_str(html_entity_decode($parsed['query']), $query);
                    if (isset($query['server'], $query['port'], $query['secret'])) {
                        $key = $query['server'] . ':' . $query['port'];
                        $secret = trim($query['secret']);
                        
                        // Detect Secret Type
                        $type = 'Standard';
                        if (str_starts_with($secret, 'dd')) $type = 'Secured'; // Randomized
                        if (str_starts_with($secret, 'ee')) $type = 'TLS';     // Fake TLS

                        $found[$key] = [
                            'server' => trim($query['server']),
                            'port'   => (int)$query['port'],
                            'secret' => $secret,
                            'type'   => $type,
                            'tg_url' => "tg://proxy?server={$query['server']}&port={$query['port']}&secret={$secret}"
                        ];
                    }
                }
            }
        }
        return array_values($found);
    }

    private function checkConnectivity(array $proxies): array {
        $results = [];
        $chunks = array_chunk($proxies, CONFIG['batch_size']);

        foreach ($chunks as $chunk) {
            $sockets = [];
            $map = [];
            foreach ($chunk as $idx => $proxy) {
                $address = "tcp://{$proxy['server']}:{$proxy['port']}";
                $s = @stream_socket_client($address, $errno, $errstr, 0, STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT);
                if ($s) {
                    $sockets[$idx] = $s;
                    $map[$idx] = ['proxy' => $proxy, 'start' => microtime(true)];
                } else {
                    $proxy['status'] = 'Offline';
                    $proxy['latency'] = null;
                    $results[] = $proxy;
                }
            }

            $timeout = CONFIG['socket_timeout'];
            $startWait = microtime(true);
            
            while (!empty($sockets) && (microtime(true) - $startWait) < $timeout) {
                $read = $write = $sockets;
                $except = null;
                if (stream_select($read, $write, $except, 0, 200000) > 0) {
                    foreach ($write as $id => $sock) {
                        $info = $map[$id];
                        $latency = round((microtime(true) - $info['start']) * 1000);
                        $p = $info['proxy'];
                        $p['status'] = 'Online';
                        $p['latency'] = $latency;
                        $results[] = $p;
                        fclose($sock);
                        unset($sockets[$id]);
                    }
                }
            }
            foreach ($sockets as $id => $sock) {
                $p = $map[$id]['proxy'];
                $p['status'] = 'Offline';
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

// Data for Template
$onlineProxies = array_filter($proxies, fn($p) => $p['status'] === 'Online');
$onlineCount = count($onlineProxies);
$totalCount = count($proxies);
$scanTimestamp = $lastScanTime; // Pass raw timestamp for JS

// Render
ob_start();
require 'template.phtml';
$htmlContent = ob_get_clean();
file_put_contents(CONFIG['output_html'], $htmlContent);

if ($isCli) echo "Generated index.html\n";
else echo $htmlContent;
?>
