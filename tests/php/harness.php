<?php

/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Fojle Rabbi (Rabib)
 *
 * Test harness: reads one request as JSON on stdin, runs the receiver and prints the status.
 */

declare(strict_types=1);

use PkgPublisher\Hooks\Receiver;

define('PKG_HOOK_TEST', true);
require dirname(__DIR__, 2) . '/web/hooks/sync.php';

$case = json_decode((string) stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
$body = (string) $case['body'];
$receiver = new Receiver((string) $case['nudge_dir'], (string) $case['secret_file']);
$status = $receiver->handle([
    'method' => (string) $case['method'],
    'address' => (string) $case['address'],
    'contentLength' => $case['content_length'],
    'signature' => $case['signature'],
    'event' => $case['event'],
    'delivery' => $case['delivery'],
    'readBody' => static fn (int $limit): string => substr($body, 0, $limit),
    'now' => (int) $case['now'],
]);
echo $status;
