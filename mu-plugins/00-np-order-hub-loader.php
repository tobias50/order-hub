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

// MU-plugins do not run activation hooks, so ensure DB table exists once loaded.
if (function_exists('np_order_hub_activate') && function_exists('np_order_hub_table_name')) {
    global $wpdb;
    if (isset($wpdb) && $wpdb instanceof wpdb) {
        $tables = array();
        $orders_table = (string) np_order_hub_table_name();
        if ($orders_table !== '') {
            $tables[] = $orders_table;
        }
        if (function_exists('np_order_hub_production_error_table_name')) {
            $production_table = (string) np_order_hub_production_error_table_name();
            if ($production_table !== '') {
                $tables[] = $production_table;
            }
        }

        foreach ($tables as $table) {
            $exists = (string) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
            if ($exists !== $table) {
                np_order_hub_activate();
                break;
            }
        }
    }
}
