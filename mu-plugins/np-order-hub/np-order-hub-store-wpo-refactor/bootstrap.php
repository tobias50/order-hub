<?php
if (!defined('ABSPATH')) {
    exit;
}

$np_refactor_main = __DIR__ . '/includes/modules/001-runtime-main.php';
if (is_readable($np_refactor_main)) {
    require_once $np_refactor_main;
}
