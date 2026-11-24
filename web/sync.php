<?php

/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Fojle Rabbi (Rabib)
 *
 * Webhook receiver for GitHub "release published" deliveries.
 *
 * It holds no publish privileges: a valid delivery only touches the nudge file, which a systemd
 * path unit turns into one publisher run. Every answer has a fixed status and an empty body.
 *
 * Rules, in order: POST only (405); per-address throttle (429); Content-Length present and at
 * most 1 MiB (413); X-Hub-Signature-256 over the raw body (401); ping and non-release events (200);
 * a repeated delivery GUID (200, no second nudge, counted for the status view); then the nudge
 * (202).
 */

declare(strict_types=1);

namespace PkgPublisher\Hooks;

use Closure;

// The file declares symbols and, last, serves the request; the test harness defines the constant
// to load the declarations only.

const NUDGE_DIR = '/var/lib/php-pkg-publisher/nudge';
const SECRET_FILE = '/etc/php-pkg-publisher-webhook/secret';
const BODY_LIMIT = 1048576;
const THROTTLE_LIMIT = 20;
const THROTTLE_WINDOW = 60;
const GUID_WINDOW = 120;
const DUPLICATES_FILE = 'duplicates';
const MAX_DUPLICATES = 999999999;
const MAX_ENTRIES = 1000;
const MAX_CLEANUP = 20;
const MIN_SECRET_BYTES = 16;
const NUDGE_ATTEMPTS = 2;

/**
 * @phpstan-type RequestData array{
 *     method: string,
 *     address: string,
 *     contentLength: ?string,
 *     signature: ?string,
 *     event: ?string,
 *     delivery: ?string,
 *     readBody: Closure(int): string,
 *     now: int
 * }
 */
final readonly class Receiver
{
    /**
     * @param Closure(string): void $report Called with a fixed reason code for every 500: never a
     *                                      path, a secret or an exception message.
     * @param (Closure(string): (resource|false))|null $create Exclusive create of the nudge file,
     *                                      for tests that need a race the file system cannot give.
     */
    public function __construct(
        private string $nudgeDir,
        private string $secretFile,
        private Closure $report,
        private ?Closure $create = null
    ) {
    }

    private function fail(string $reason): int
    {
        ($this->report)($reason);
        return 500;
    }

    /** Number of entries in a directory, counting no further than the limit plus one. */
    private function countEntries(string $directory, int $limit): int
    {
        $handle = @opendir($directory);
        if ($handle === false) {
            return 0;
        }
        $count = 0;
        while (($name = readdir($handle)) !== false && $count <= $limit) {
            if ($name !== '.' && $name !== '..') {
                ++$count;
            }
        }
        closedir($handle);
        return $count;
    }

    /** Remove up to MAX_CLEANUP entries older than their window. */
    private function sweep(string $directory, int $window, int $now): void
    {
        $handle = @opendir($directory);
        if ($handle === false) {
            return;
        }
        $removed = 0;
        while (($name = readdir($handle)) !== false && $removed < MAX_CLEANUP) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $directory . '/' . $name;
            $modified = @filemtime($path);
            if ($modified !== false && $now - $modified >= $window && @unlink($path)) {
                ++$removed;
            }
        }
        closedir($handle);
    }

    private function ensureDirectory(string $path): bool
    {
        return is_dir($path) || @mkdir($path, 0700) || is_dir($path);
    }

    /** One key per client: an IPv4 address, or an IPv6 /64, whatever the spelling. */
    private function addressKey(string $address): string
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return hash('sha256', 'raw:' . $address);
        }
        if (strlen($packed) === 16) {
            $packed = substr($packed, 0, 8);
        }
        return hash('sha256', 'ip:' . bin2hex($packed));
    }

    /**
     * True when this address is over its limit; records the request unless the table is full.
     *
     * @param RequestData $request
     */
    private function throttled(array $request): bool
    {
        $directory = $this->nudgeDir . '/thr';
        if (!$this->ensureDirectory($directory)) {
            return false;
        }
        $path = $directory . '/' . $this->addressKey($request['address']);
        if (!file_exists($path) && $this->countEntries($directory, MAX_ENTRIES) > MAX_ENTRIES) {
            return false;
        }
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return false;
        }
        $limited = false;
        if (flock($handle, LOCK_EX)) {
            $fields = explode(' ', (string) stream_get_contents($handle));
            $start = ctype_digit($fields[0]) ? (int) $fields[0] : 0;
            $count = isset($fields[1]) && ctype_digit($fields[1]) ? (int) $fields[1] : 0;
            if ($request['now'] - $start >= THROTTLE_WINDOW) {
                $start = $request['now'];
                $count = 0;
            }
            ++$count;
            $limited = $count > THROTTLE_LIMIT;
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $start . ' ' . $count);
            flock($handle, LOCK_UN);
        }
        fclose($handle);
        @touch($path, $request['now']);
        return $limited;
    }

    /** @param RequestData $request */
    private function validSignature(array $request, string $body, string $secret): bool
    {
        $given = $request['signature'];
        if ($given === null || preg_match('/\Asha256=[0-9a-f]{64}\z/', $given) !== 1) {
            return false;
        }
        return hash_equals('sha256=' . hash_hmac('sha256', $body, $secret), $given);
    }

    private function readSecret(): ?string
    {
        $raw = @file_get_contents($this->secretFile, false, null, 0, 4096);
        if ($raw === false) {
            return null;
        }
        $secret = rtrim($raw, "\r\n");
        return strlen($secret) >= MIN_SECRET_BYTES ? $secret : null;
    }

    /** True for a published release, false for any other action; null when the body is unusable. */
    private function isPublishedRelease(string $body): ?bool
    {
        $payload = json_decode($body, true, 16);
        if (!is_array($payload)) {
            return null;
        }
        return ($payload['action'] ?? null) === 'published';
    }

    private function guidPath(string $delivery): string
    {
        return $this->nudgeDir . '/guid/' . hash('sha256', strtolower($delivery));
    }

    /**
     * 200 for a delivery already seen in the window, 429 when the table is full, else null.
     *
     * @param RequestData $request
     */
    private function seenStatus(array $request, string $delivery): ?int
    {
        $directory = $this->nudgeDir . '/guid';
        if (!$this->ensureDirectory($directory)) {
            return $this->fail('guid-directory-unusable');
        }
        $modified = @filemtime($this->guidPath($delivery));
        if ($modified !== false && $request['now'] - $modified < GUID_WINDOW) {
            $this->countDuplicate($request['now']);
            return 200;
        }
        if ($modified === false && $this->countEntries($directory, MAX_ENTRIES) > MAX_ENTRIES) {
            return 429;
        }
        return null;
    }

    /**
     * Count a repeated delivery for the status view: one fixed-width line, "<count> <time of the
     * last one>" (nine and twelve digits). The answer never depends on it, so any failure here is
     * ignored. The file is made readable to the publisher user, who is not the web server's user,
     * at once and whatever this process's umask; the directory keeps everyone else out. The line
     * is written whole over the old one, so a reader never sees the file empty or half made.
     */
    private function countDuplicate(int $now): void
    {
        $path = $this->nudgeDir . '/' . DUPLICATES_FILE;
        // PHP's 'c+' mode follows a link, so refuse one
        if (is_link($path)) {
            return;
        }
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return;
        }
        @chmod($path, 0644);
        if (flock($handle, LOCK_EX)) {
            $fields = explode(' ', (string) stream_get_contents($handle));
            $count = ctype_digit($fields[0]) ? (int) $fields[0] : 0;
            $line = sprintf('%09d %012d', min($count + 1, MAX_DUPLICATES), $now);
            rewind($handle);
            fwrite($handle, $line);
            ftruncate($handle, strlen($line));
            flock($handle, LOCK_UN);
        }
        fclose($handle);
    }

    /** Remember a delivery only after its nudge was made, so a failed one can be redelivered. */
    private function remember(string $delivery, int $now): void
    {
        $path = $this->guidPath($delivery);
        if (@file_put_contents($path, '') !== false) {
            @touch($path, $now);
        }
    }

    /**
     * Create the nudge file. One that is already there counts as success, whoever owns it: the
     * publisher may have re-created it as its own, and an existing nudge means a run is pending.
     * One that vanishes between the failed create and the check was just taken by the publisher,
     * so one more try is made; a second failure is a real fault. The publisher skips a pass that
     * finds no change.
     */
    private function nudge(): bool
    {
        $path = $this->nudgeDir . '/sync';
        for ($attempt = 0; $attempt < NUDGE_ATTEMPTS; ++$attempt) {
            // PHP's exclusive mode still follows a dangling link and creates its target, so refuse links.
            if (is_link($path)) {
                return false;
            }
            $handle = ($this->create ?? static fn (string $file) => @fopen($file, 'x'))($path);
            if ($handle !== false) {
                fclose($handle);
                return true;
            }
            if (is_file($path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decide the status of one request and, for a new published release, touch the nudge file.
     *
     * @param RequestData $request
     */
    public function handle(array $request): int
    {
        if ($request['method'] !== 'POST') {
            return 405;
        }
        // Two users share this directory (the publisher unlinks `sync`), so it is made by the
        // operator, never by the receiver.
        if (!is_dir($this->nudgeDir)) {
            return $this->fail('nudge-directory-missing');
        }
        $this->sweep($this->nudgeDir . '/thr', THROTTLE_WINDOW, $request['now']);
        $this->sweep($this->nudgeDir . '/guid', GUID_WINDOW, $request['now']);
        if ($this->throttled($request)) {
            return 429;
        }
        $length = $request['contentLength'];
        if ($length === null || !ctype_digit($length) || strlen($length) > 8 || (int) $length > BODY_LIMIT) {
            return 413;
        }
        $body = $request['readBody'](BODY_LIMIT + 1);
        if (strlen($body) > BODY_LIMIT) {
            return 413;
        }
        $secret = $this->readSecret();
        if ($secret === null) {
            return $this->fail('secret-unusable');
        }
        if (!$this->validSignature($request, $body, $secret)) {
            return 401;
        }
        if ($request['event'] !== 'release') {
            return 200;
        }
        $published = $this->isPublishedRelease($body);
        if ($published === null) {
            return 400;
        }
        if (!$published) {
            return 200;
        }
        $delivery = $request['delivery'];
        if ($delivery === null || preg_match('/\A[0-9A-Fa-f-]{36}\z/', $delivery) !== 1) {
            return 400;
        }
        $seen = $this->seenStatus($request, $delivery);
        if ($seen !== null) {
            return $seen;
        }
        if (!$this->nudge()) {
            return $this->fail('nudge-failed');
        }
        $this->remember($delivery, $request['now']);
        return 202;
    }
}

function serverValue(string $name): ?string
{
    $value = $_SERVER[$name] ?? null;
    return is_string($value) ? $value : null;
}

/**
 * Run the handler; whatever it throws becomes a 500 that names only the exception class, so an
 * error never reaches the client and no message (which may hold a path) reaches the log.
 *
 * @param Closure(): int $handle
 * @param Closure(string): void $report
 */
function guarded(Closure $handle, Closure $report): int
{
    try {
        return $handle();
    } catch (\Throwable $error) {
        $report('internal-error ' . $error::class);
        return 500;
    }
}

/** Answer the request from the web server's variables. */
function serve(): void
{
    // Nothing an error says may reach the client; the reason codes go to the error log.
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    header_remove('X-Powered-By');
    $report = static function (string $reason): void {
        error_log('pkg-hook: ' . $reason);
    };
    $address = serverValue('HTTP_CF_CONNECTING_IP') ?? serverValue('REMOTE_ADDR') ?? '';
    if (filter_var($address, FILTER_VALIDATE_IP) === false) {
        $address = serverValue('REMOTE_ADDR') ?? 'unknown';
    }
    $request = [
        'method' => serverValue('REQUEST_METHOD') ?? '',
        'address' => $address,
        'contentLength' => serverValue('CONTENT_LENGTH'),
        'signature' => serverValue('HTTP_X_HUB_SIGNATURE_256'),
        'event' => serverValue('HTTP_X_GITHUB_EVENT'),
        'delivery' => serverValue('HTTP_X_GITHUB_DELIVERY'),
        'readBody' => static fn (int $limit): string => (string) file_get_contents(
            'php://input',
            false,
            null,
            0,
            max(0, $limit)
        ),
        'now' => time(),
    ];
    $receiver = new Receiver(NUDGE_DIR, SECRET_FILE, $report);
    $status = guarded(static fn (): int => $receiver->handle($request), $report);
    http_response_code($status);
    header('Cache-Control: no-store');
    if ($status === 405) {
        header('Allow: POST');
    }
}

if (!defined('PKG_HOOK_TEST')) {
    serve();
}
