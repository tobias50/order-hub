<?php
if (!defined('ABSPATH')) {
    exit;
}

$np_runtime_segments = glob(__DIR__ . '/001-runtime-main.d/001-runtime-main-seg-*.php');
if (is_array($np_runtime_segments)) {
    sort($np_runtime_segments, SORT_NATURAL);
    foreach ($np_runtime_segments as $np_runtime_segment) {
        if (is_readable($np_runtime_segment)) {
            require_once $np_runtime_segment;
        }
    }
}
