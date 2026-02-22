<?php
/**
 * Plugin Name: NP Order Hub
 * Description: Collect orders from multiple WooCommerce stores and display a central list.
 * Version: 0.2.2
 * Author: Nordicprofil
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('NP_ORDER_HUB_MAIN_FILE')) {
    define('NP_ORDER_HUB_MAIN_FILE', __FILE__);
}

$np_refactor_bootstrap = __DIR__ . '/np-order-hub-refactor/bootstrap.php';
if (is_readable($np_refactor_bootstrap)) {
    require_once $np_refactor_bootstrap;
}
