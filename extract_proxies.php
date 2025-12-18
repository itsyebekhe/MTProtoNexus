<?php
declare(strict_types=1);

/**
 * Telegram Proxy Scanner - Static Generator Edition
 * Fixed for GitHub Actions & Pages
 */

// --- Configuration ---
const CONFIG = [
    'input_file'      => 'usernames.json',
    'output_json'     => 'extracted_proxies.json',
    'output_html'     => 'index.html', // We must save to this file
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
        if (empty($usernames)) {
            echo "No usernames found in " . CONFIG['input_file'] . "\n";
            return [];
        }

        echo "Fetching " . count($usernames) . " channels...\n";
        $rawHtml = $this->fetchChannels($usernames);
        
        echo "Extracting proxies...\n";
        $proxies = $this->extractProxies($rawHtml);
        
        echo "Checking connectivity for " . count($proxies) . " proxies...\n";
        $checkedProxies = $this->checkConnectivity($proxies);
        
        // Sort: Online first, then by latency
        usort($checkedProxies, function ($a, $b) {
            if ($a['status'] === 'Online' && $b['status'] !== 'Online') return -1;
            if ($a['status'] !== 'Online' && $b['status'] === 'Online') return 1;
            return ($a['latency'] ?? 9999) <=> ($b['latency'] ?? 9999);
        });

        // Save JSON
        file_put_contents(CONFIG['output_json'], json_encode($checkedProxies, JSON_PRETTY_PRINT));
        echo "Saved JSON to " . CONFIG['output_json'] . "\n";
        
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
                        $found[$key] = [
                            'server' => trim($query['server']),
                            'port'   => (int)$query['port'],
                            'secret' => trim($query['secret']),
                            'tg_url' => "tg://proxy?server={$query['server']}&port={$query['port']}&secret={$query['secret']}"
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

// --- Controller Logic ---

// Determine if we are running in CLI (GitHub Actions)
$isCli = (php_sapi_name() === 'cli');

// Determine if we should scan
$shouldScan = false;
$lastScanTime = file_exists(CONFIG['output_json']) ? filemtime(CONFIG['output_json']) : 0;
$timeDiff = time() - $lastScanTime;

if ($isCli || !file_exists(CONFIG['output_json']) || $timeDiff > CONFIG['cache_duration'] || isset($_GET['scan'])) {
    $shouldScan = true;
}

if ($shouldScan) {
    $scanner = new ProxyScanner();
    $proxies = $scanner->run();
    $lastScanTime = time();
} else {
    $proxies = json_decode(file_get_contents(CONFIG['output_json']), true);
}

// Prepare Data for Template
$onlineCount = count(array_filter($proxies, fn($p) => $p['status'] === 'Online'));
$totalCount = count($proxies);
$lastUpdateStr = date('H:i:s Y-m-d', $lastScanTime);

// --- RENDER AND SAVE ---

// 1. Start Output Buffering
ob_start();

// 2. Load the Template (it will echo into the buffer)
require 'template.phtml';

// 3. Get the contents
$htmlContent = ob_get_clean();

// 4. SAVE the index.html file (Crucial for GitHub Pages)
file_put_contents(CONFIG['output_html'], $htmlContent);

if ($isCli) {
    echo "Successfully generated " . CONFIG['output_html'] . " (" . strlen($htmlContent) . " bytes)\n";
} else {
    // If accessed via browser, show the content
    echo $htmlContent;
}
?>
