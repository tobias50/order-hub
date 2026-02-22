<?php
/**
 * Plugin Name: NP Order Hub - WPO Access Key
 * Description: Adds packing slip access data to WooCommerce webhooks and exposes token-protected packing slip endpoints.
 * Version: 0.2.10
 * Author: Nordicprofil
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('NP_ORDER_HUB_WPO_MAIN_FILE')) {
    define('NP_ORDER_HUB_WPO_MAIN_FILE', __FILE__);
}

$np_refactor_bootstrap = __DIR__ . '/np-order-hub-store-wpo-refactor/bootstrap.php';
if (is_readable($np_refactor_bootstrap)) {
    require_once $np_refactor_bootstrap;
}
