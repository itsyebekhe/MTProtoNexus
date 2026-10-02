<?php
declare(strict_types=1);

/**
 * Telegram Proxy Scanner - High Performance Optimized Edition
 */

const CONFIG = [
    'input_file'      => __DIR__ . '/usernames.json',
    'output_json'     => __DIR__ . '/extracted_proxies.json',
    'output_html'     => __DIR__ . '/index.html',
    'cache_duration'  => 3600,
    'socket_timeout'  => 2.0,   // seconds (float supported)
    'http_concurrency'=> 25,    // Max parallel HTTP requests
    'socket_batch'    => 64,    // Sockets to poll simultaneously
];

class ProxyScanner {
    private const USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    ];

    public function run(): array {
        echo "Starting Scan...\n";
        $usernames = $this->loadUsernames();
        if (empty($usernames)) {
            echo "No channels found.\n";
            return [];
        }

        $rawChannels = $this->fetchChannels($usernames);
        $proxies = $this->extractProxies($rawChannels);
        
        echo "Found " . count($proxies) . " unique valid configurations. Testing connectivity...\n";
        $checkedProxies = $this->checkConnectivity($proxies);
        
        // Smart Sort: Online status first, then ascending latency
        usort($checkedProxies, static function (array $a, array $b): int {
            $aOnline = ($a['status'] === 'Online');
            $bOnline = ($b['status'] === 'Online');

            if ($aOnline !== $bOnline) {
                return $bOnline <=> $aOnline;
            }
            return ($a['latency'] ?? 99999) <=> ($b['latency'] ?? 99999);
        });

        $this->atomicWrite(CONFIG['output_json'], json_encode($checkedProxies, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return $checkedProxies;
    }

    private function loadUsernames(): array {
        if (!is_file(CONFIG['input_file'])) {
            return [];
        }
        $data = json_decode(file_get_contents(CONFIG['input_file']), true);
        return is_array($data) ? array_values(array_filter(array_map('trim', $data))) : [];
    }

    /**
     * Non-blocking rolling curl multi-exec
     */
    private function fetchChannels(array $usernames): array {
        $mh = curl_multi_init();
        $results = [];
        $running = 0;
        $maxConcurrent = (int)CONFIG['http_concurrency'];

        $queue = array_unique($usernames);
        $activeHandles = [];

        $enqueue = function() use ($mh, &$queue, &$activeHandles) {
            $user = array_pop($queue);
            if ($user === null) return false;

            $ch = curl_init('https://telegram.me/s/' . rawurlencode($user));
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_USERAGENT      => self::USER_AGENTS[array_rand(self::USER_AGENTS)],
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_ENCODING       => '', // auto gzip/deflate
            ]);
            curl_multi_add_handle($mh, $ch);
            $activeHandles[(int)$ch] = $ch;
            return true;
        };

        // Seed initial pool
        for ($i = 0; $i < $maxConcurrent && !empty($queue); $i++) {
            $enqueue();
        }

        do {
            $status = curl_multi_exec($mh, $running);

            // Read completed transfers
            while ($info = curl_multi_info_read($mh)) {
                $ch = $info['handle'];
                $id = (int)$ch;

                if ($info['result'] === CURLE_OK && curl_getinfo($ch, CURLINFO_RESPONSE_CODE) === 200) {
                    $results[] = curl_multi_getcontent($ch);
                }

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($activeHandles[$id]);

                // Pull next item
                $enqueue();
            }

            if ($running > 0) {
                curl_multi_select($mh, 0.05);
            }
        } while ($running > 0 || !empty($queue));

        curl_multi_close($mh);
        return $results;
    }

    /**
     * Fast parsing of tg:// links without running heavy preg_match on all parameters
     */
    private function extractProxies(array $htmlPages): array {
        $proxies = [];

        // Match the complete URI string
        $pattern = '/(?:tg:\/\/|https?:\/\/t(?:elegram)?\.me\/)proxy\?([a-zA-Z0-9_\-\.\%&=]+)/i';

        foreach ($htmlPages as $html) {
            if (!preg_match_all($pattern, $html, $matches)) {
                continue;
            }

            foreach ($matches[1] as $rawQuery) {
                // Decode query entities
                $queryString = html_entity_decode($rawQuery, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                parse_str($queryString, $params);

                if (empty($params['server']) || empty($params['port']) || empty($params['secret'])) {
                    continue;
                }

                $server = trim((string)$params['server']);
                $port   = (int)$params['port'];
                $secret = $this->cleanSecret((string)$params['secret']);

                if ($port <= 0 || $port > 65535 || !$secret || empty($server)) {
                    continue;
                }

                $key = "{$server}:{$port}";
                if (isset($proxies[$key])) {
                    continue;
                }

                $type = match (true) {
                    str_starts_with($secret, 'ee') => 'MTProto TLS',
                    str_starts_with($secret, 'dd') => 'MTProto Padded',
                    default                        => 'MTProto Simple'
                };

                $proxies[$key] = [
                    'server' => $server,
                    'port'   => $port,
                    'secret' => $secret,
                    'type'   => $type,
                    'tg_url' => "tg://proxy?server=" . rawurlencode($server) . "&port={$port}&secret={$secret}"
                ];
            }
        }

        return array_values($proxies);
    }

    /**
     * Validates MTProto Hex Secret formats
     */
    private function cleanSecret(string $secret): ?string {
        $secret = strtolower(trim($secret));

        if (!ctype_xdigit($secret)) {
            return null;
        }

        $len = strlen($secret);

        // MTProto Simple: exactly 16 bytes = 32 hex chars
        // MTProto Padded: 'dd' prefix + 16 bytes = 34 hex chars
        // MTProto TLS / FakeTLS: 'ee' prefix + 16 bytes + domain bytes >= 34 hex chars
        if ($len === 32) {
            return $secret;
        }
        if (str_starts_with($secret, 'dd') && $len === 34) {
            return $secret;
        }
        if (str_starts_with($secret, 'ee') && $len >= 34 && ($len % 2 === 0)) {
            return $secret;
        }

        return null;
    }

    /**
     * Non-blocking multi-socket TCP handshaker
     */
    private function checkConnectivity(array $proxies): array {
        $results = [];
        $batchSize = (int)(CONFIG['socket_batch'] ?? 64);
        $timeout = (float)(CONFIG['socket_timeout'] ?? 2.0);

        foreach (array_chunk($proxies, $batchSize) as $chunk) {
            $sockets = [];
            $meta    = [];

            foreach ($chunk as $idx => $proxy) {
                $address = "tcp://{$proxy['server']}:{$proxy['port']}";
                
                // Asynchronous non-blocking connect
                $socket = @stream_socket_client(
                    $address,
                    $errno,
                    $errstr,
                    $timeout,
                    STREAM_CLIENT_ASYNC_CONNECT
                );

                if ($socket !== false) {
                    stream_set_blocking($socket, false);
                    $sockets[$idx] = $socket;
                    $meta[$idx] = [
                        'proxy' => $proxy,
                        'start' => microtime(true),
                    ];
                } else {
                    $proxy['status']  = 'Offline';
                    $proxy['latency'] = null;
                    $results[] = $proxy;
                }
            }

            $deadline = microtime(true) + $timeout;

            while (!empty($sockets)) {
                $timeLeft = $deadline - microtime(true);
                if ($timeLeft <= 0) {
                    break;
                }

                $read   = null;
                $write  = $sockets;
                $except = null;

                $sec  = (int)$timeLeft;
                $usec = (int)(($timeLeft - $sec) * 1_000_000);

                $changed = @stream_select($read, $write, $except, $sec, $usec);
                if ($changed === false || $changed === 0) {
                    break;
                }

                foreach ($write as $idx => $sock) {
                    $info = $meta[$idx];
                    $proxy = $info['proxy'];

                    // stream_select on write will fire if connected OR on error.
                    // We verify connection using stream_socket_get_name()
                    if (@stream_socket_get_name($sock, true) !== false) {
                        $proxy['status']  = 'Online';
                        $proxy['latency'] = (int)round((microtime(true) - $info['start']) * 1000);
                    } else {
                        $proxy['status']  = 'Offline';
                        $proxy['latency'] = null;
                    }

                    $results[] = $proxy;
                    @fclose($sock);
                    unset($sockets[$idx], $meta[$idx]);
                }
            }

            // Timed out sockets
            foreach ($sockets as $idx => $sock) {
                $proxy = $meta[$idx]['proxy'];
                $proxy['status']  = 'Offline';
                $proxy['latency'] = null;
                $results[] = $proxy;
                @fclose($sock);
            }
        }

        return $results;
    }

    private function atomicWrite(string $path, string $content): void {
        $temp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        file_put_contents($temp, $content, LOCK_EX);
        rename($temp, $path);
    }
}

// --- Execution Lifecycle ---
$isCli = (PHP_SAPI === 'cli');
$lastScanTime = is_file(CONFIG['output_json']) ? filemtime(CONFIG['output_json']) : 0;
$shouldScan = $isCli 
    || !is_file(CONFIG['output_json']) 
    || (time() - $lastScanTime) > CONFIG['cache_duration'] 
    || isset($_GET['scan']);

if ($shouldScan) {
    $scanner = new ProxyScanner();
    $proxies = $scanner->run();
    $lastScanTime = time();
} else {
    $proxies = json_decode(file_get_contents(CONFIG['output_json']), true) ?? [];
}

$onlineCount   = count(array_filter($proxies, static fn($p) => ($p['status'] ?? '') === 'Online'));
$totalCount    = count($proxies);
$scanTimestamp = $lastScanTime;

// Render template safely
if (is_file(__DIR__ . '/template.phtml')) {
    ob_start();
    require __DIR__ . '/template.phtml';
    $htmlContent = ob_get_clean();

    $tempFile = CONFIG['output_html'] . '.tmp';
    file_put_contents($tempFile, $htmlContent, LOCK_EX);
    rename($tempFile, CONFIG['output_html']);

    if ($isCli) {
        echo "Generated index.html with {$onlineCount}/{$totalCount} online proxies.\n";
    } else {
        echo $htmlContent;
    }
}
