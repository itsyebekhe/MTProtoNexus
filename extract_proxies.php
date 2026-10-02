<?php
declare(strict_types=1);

/**
 * Telegram Proxy Scanner - High Performance Optimized
 */

const CONFIG = [
    'input_file'      => 'usernames.json',
    'output_json'     => 'extracted_proxies.json',
    'output_html'     => 'index.html',
    'cache_duration'  => 3600,
    'socket_timeout'  => 2.5,
    'curl_timeout'    => 8,
    'curl_max_concur' => 30,
    'socket_batch'    => 64,
];

class ProxyScanner {
    private const USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    ];

    public function run(): array {
        echo "Starting Scan...\n";
        $usernames = $this->loadUsernames();
        if (empty($usernames)) {
            echo "No usernames found in input file.\n";
            return [];
        }

        // Fetch & extract on-the-fly to minimize peak memory
        $proxies = $this->fetchAndExtractProxies($usernames);
        $totalFound = count($proxies);
        echo "Found {$totalFound} unique valid proxies. Checking connectivity...\n";

        if ($totalFound === 0) {
            return [];
        }

        $checkedProxies = $this->checkConnectivity($proxies);

        // Sort: Online first, then by lowest latency
        usort($checkedProxies, static function (array $a, array $b): int {
            $aOnline = ($a['status'] === 'Online');
            $bOnline = ($b['status'] === 'Online');

            if ($aOnline !== $bOnline) {
                return $bOnline <=> $aOnline;
            }

            return ($a['latency'] ?? 9999) <=> ($b['latency'] ?? 9999);
        });

        file_put_contents(CONFIG['output_json'], json_encode($checkedProxies, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return $checkedProxies;
    }

    private function loadUsernames(): array {
        if (!file_exists(CONFIG['input_file'])) {
            return [];
        }
        $data = json_decode((string)file_get_contents(CONFIG['input_file']), true);
        return is_array($data) ? array_filter(array_map('trim', $data)) : [];
    }

    /**
     * Uses a rolling cURL multi queue and extracts proxies on-the-fly
     */
    private function fetchAndExtractProxies(array $usernames): array {
        $mh = curl_multi_init();
        $handles = [];
        $uniqueProxies = [];
        $maxConcurrent = (int)CONFIG['curl_max_concur'];

        // Worker to push new handles
        $addHandle = function (string $user) use ($mh, &$handles): void {
            $ch = curl_init('https://telegram.me/s/' . rawurlencode($user));
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT        => CONFIG['curl_timeout'],
                CURLOPT_USERAGENT      => self::USER_AGENTS[array_rand(self::USER_AGENTS)],
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_ENCODING       => '', // enables gzip/deflate automatically
                CURLOPT_NOSIGNAL       => 1,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[(int)$ch] = $ch;
        };

        // Seed initial pool
        while (!empty($usernames) && count($handles) < $maxConcurrent) {
            $addHandle(array_shift($usernames));
        }

        do {
            $status = curl_multi_exec($mh, $active);

            // Read completed transfers
            while ($info = curl_multi_info_read($mh)) {
                $ch = $info['handle'];
                $id = (int)$ch;

                if ($info['result'] === CURLE_OK) {
                    $html = (string)curl_multi_getcontent($ch);
                    $this->extractProxiesFromHtml($html, $uniqueProxies);
                    unset($html); // Prompt GC
                }

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($handles[$id]);

                // Enqueue next
                if (!empty($usernames)) {
                    $addHandle(array_shift($usernames));
                }
            }

            if ($active && $status === CURLM_OK) {
                curl_multi_select($mh, 0.1);
            }
        } while ($active || !empty($handles));

        curl_multi_close($mh);
        return array_values($uniqueProxies);
    }

    /**
     * Fast proxy extraction: regex only searches for proxy query strings
     */
    private function extractProxiesFromHtml(string &$html, array &$found): void {
        // Fast match on tg:// or t.me proxy links
        if (!preg_match_all('/(?:tg:\/\/|t\.me\/)proxy\?([^"\'\s<>]+)/i', $html, $matches)) {
            return;
        }

        foreach ($matches[1] as $query) {
            // Decode entity-encoded ampersands (&amp; -> &)
            $decodedQuery = str_replace('&amp;', '&', $query);
            parse_str($decodedQuery, $params);

            $server = isset($params['server']) ? trim((string)$params['server']) : '';
            $port   = filter_var($params['port'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
            $secret = isset($params['secret']) ? $this->cleanSecret((string)$params['secret']) : null;

            if ($server === '' || $port === false || $secret === null) {
                continue;
            }

            $key = "{$server}:{$port}";
            if (isset($found[$key])) {
                continue;
            }

            $type = match (true) {
                str_starts_with($secret, 'dd') => 'MTProto Secure',
                str_starts_with($secret, 'ee') => 'MTProto TLS',
                default                        => 'MTProto'
            };

            $found[$key] = [
                'server' => $server,
                'port'   => $port,
                'secret' => $secret,
                'type'   => $type,
                'tg_url' => "tg://proxy?server={$server}&port={$port}&secret={$secret}",
            ];
        }
    }

    private function cleanSecret(string $secret): ?string {
        $secret = strtolower(trim($secret));

        if (!ctype_xdigit($secret)) {
            return null;
        }

        $len = strlen($secret);

        if (str_starts_with($secret, 'dd')) {
            return ($len === 32 || $len === 34) ? $secret : null;
        }

        if (str_starts_with($secret, 'ee')) {
            return ($len >= 34) ? $secret : null;
        }

        return ($len === 32) ? $secret : null;
    }

    /**
     * High-speed non-blocking asynchronous TCP handshake checker
     */
    private function checkConnectivity(array $proxies): array {
        $results = [];
        $batchSize = (int)CONFIG['socket_batch'];
        $timeout = (float)CONFIG['socket_timeout'];
        $chunks = array_chunk($proxies, $batchSize);

        foreach ($chunks as $chunk) {
            $sockets = [];
            $map = [];

            foreach ($chunk as $idx => $proxy) {
                // Non-blocking connection initiation
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
                    $proxy['status'] = 'Offline';
                    $proxy['latency'] = null;
                    $results[] = $proxy;
                }
            }

            $deadline = microtime(true) + $timeout;

            while (!empty($sockets)) {
                $remaining = $deadline - microtime(true);
                if ($remaining <= 0) {
                    break;
                }

                $read = null;
                $write = $sockets;
                $except = null;

                $sec = (int)$remaining;
                $usec = (int)(($remaining - $sec) * 1_000_000);

                $ready = @stream_select($read, $write, $except, $sec, $usec);
                if ($ready === false || $ready === 0) {
                    break;
                }

                foreach ($write as $id => $sock) {
                    $info = $map[$id];
                    $p = $info['proxy'];

                    // A writable socket is either connected or rejected.
                    // stream_socket_get_name confirms if the handshake succeeded without blocking.
                    if (@stream_socket_get_name($sock, true) !== false) {
                        $p['status']  = 'Online';
                        $p['latency'] = (int)round((microtime(true) - $info['start']) * 1000);
                    } else {
                        $p['status']  = 'Offline';
                        $p['latency'] = null;
                    }

                    $results[] = $p;
                    fclose($sock);
                    unset($sockets[$id], $map[$id]);
                }
            }

            // Any remaining sockets timed out
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

// --- Execution ---
$isCli = (PHP_SAPI === 'cli');
$lastScanTime = file_exists(CONFIG['output_json']) ? filemtime(CONFIG['output_json']) : 0;
$cacheExpired = (time() - $lastScanTime) > CONFIG['cache_duration'];
$forceScan = isset($_GET['scan']);

$shouldScan = $isCli || !file_exists(CONFIG['output_json']) || $cacheExpired || $forceScan;

if ($shouldScan) {
    $scanner = new ProxyScanner();
    $proxies = $scanner->run();
    $lastScanTime = time();
} else {
    $proxies = json_decode((string)file_get_contents(CONFIG['output_json']), true) ?? [];
}

// Prepare View Data
$onlineCount = 0;
foreach ($proxies as $p) {
    if ($p['status'] === 'Online') {
        $onlineCount++;
    }
}
$totalCount = count($proxies);
$scanTimestamp = $lastScanTime;

// Render
if (file_exists('template.phtml')) {
    ob_start();
    require 'template.phtml';
    $htmlContent = ob_get_clean();
    file_put_contents(CONFIG['output_html'], $htmlContent);

    if ($isCli) {
        echo "Generated " . CONFIG['output_html'] . " with {$onlineCount}/{$totalCount} online proxies.\n";
    } else {
        echo $htmlContent;
    }
}
