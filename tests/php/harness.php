<?php

/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Fojle Rabbi (Rabib)
 *
 * Test harness: reads one request as JSON on stdin, runs the receiver the way serve() does
 * (through guarded()) and prints {"status": int, "reasons": [string]} as JSON.
 */

declare(strict_types=1);

use PkgPublisher\Hooks\Receiver;

use function PkgPublisher\Hooks\guarded;

define('PKG_HOOK_TEST', true);
require dirname(__DIR__, 2) . '/web/sync.php';

$case = json_decode((string) stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
$body = (string) $case['body'];
$reasons = [];
$report = static function (string $reason) use (&$reasons): void {
    $reasons[] = $reason;
};
// "fail_creates" makes that many exclusive creates of the nudge fail while the file stays absent,
// which is what the receiver sees when the publisher takes the nudge between its two looks.
$failures = (int) ($case['fail_creates'] ?? 0);
$create = static function (string $file) use (&$failures) {
    if ($failures > 0) {
        --$failures;
        return false;
    }
    return @fopen($file, 'x');
};
$receiver = new Receiver(
    (string) $case['nudge_dir'],
    (string) $case['secret_file'],
    $report,
    $failures > 0 ? $create : null
);
$readBody = static function (int $limit) use ($body, $case): string {
    if (($case['read_error'] ?? false) === true) {
        throw new RuntimeException('cannot read /etc/secret-path');
    }
    return substr($body, 0, $limit);
};
$request = [
    'method' => (string) $case['method'],
    'address' => (string) $case['address'],
    'contentLength' => $case['content_length'],
    'signature' => $case['signature'],
    'event' => $case['event'],
    'delivery' => $case['delivery'],
    'readBody' => $readBody,
    'now' => (int) $case['now'],
];
$status = guarded(static fn (): int => $receiver->handle($request), $report);
echo json_encode(['status' => $status, 'reasons' => $reasons], JSON_THROW_ON_ERROR);
