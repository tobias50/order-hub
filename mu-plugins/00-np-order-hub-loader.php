<?php
/**
 * Plugin Name: NP Order Hub (MU Loader)
 * Description: Loads NP Order Hub from mu-plugins/np-order-hub.
 */

if (!defined('ABSPATH')) {
    exit;
}

$np_order_hub_main = WPMU_PLUGIN_DIR . '/np-order-hub/np-order-hub.php';
if (is_readable($np_order_hub_main)) {
    require_once $np_order_hub_main;
}
