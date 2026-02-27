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

define('NP_ORDER_HUB_VERSION', '0.2.2');

define('NP_ORDER_HUB_OPTION_STORES', 'np_order_hub_stores');

define('NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE', 'legacy');

define('NP_ORDER_HUB_PER_PAGE', 30);

define('NP_ORDER_HUB_DELIVERY_BUCKET_KEY', 'np_order_hub_delivery_bucket');
define('NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED', 'scheduled');

define('NP_ORDER_HUB_PUSHOVER_ENABLED_OPTION', 'np_order_hub_pushover_enabled');
define('NP_ORDER_HUB_PUSHOVER_USER_OPTION', 'np_order_hub_pushover_user');
define('NP_ORDER_HUB_PUSHOVER_TOKEN_OPTION', 'np_order_hub_pushover_token');
define('NP_ORDER_HUB_PUSHOVER_TITLE_OPTION', 'np_order_hub_pushover_title');
define('NP_ORDER_HUB_PUSHOVER_LOGO_ENABLED_OPTION', 'np_order_hub_pushover_logo_enabled');
define('NP_ORDER_HUB_PUSHOVER_LOGO_OPTION', 'np_order_hub_pushover_logo');
define('NP_ORDER_HUB_HISTORICAL_REVENUE_OPTION', 'np_order_hub_historical_revenue');
define('NP_ORDER_HUB_MANUAL_REVENUE_OPTION', 'np_order_hub_manual_revenue');
define('NP_ORDER_HUB_VAT_RATE', 0.25);
define('NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION', 'np_order_hub_help_scout_token');
define('NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION', 'np_order_hub_help_scout_mailbox');
define('NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION', 'np_order_hub_help_scout_default_status');
define('NP_ORDER_HUB_HELP_SCOUT_USER_OPTION', 'np_order_hub_help_scout_user');
define('NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION', 'np_order_hub_help_scout_client_id');
define('NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION', 'np_order_hub_help_scout_client_secret');
define('NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION', 'np_order_hub_help_scout_refresh_token');
define('NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION', 'np_order_hub_help_scout_expires_at');
define('NP_ORDER_HUB_HELP_SCOUT_WEBHOOK_SECRET_OPTION', 'np_order_hub_help_scout_webhook_secret');
define('NP_ORDER_HUB_HELP_SCOUT_AUTO_LOOKUP_OPTION', 'np_order_hub_help_scout_auto_lookup');
define('NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION', 'np_order_hub_connector_setup_key');
define('NP_ORDER_HUB_PRINT_QUEUE_OPTION', 'np_order_hub_print_queue_jobs');
define('NP_ORDER_HUB_PRINT_QUEUE_EVENT', 'np_order_hub_process_print_job');
define('NP_ORDER_HUB_PRINT_QUEUE_TICK_EVENT', 'np_order_hub_print_queue_tick');
define('NP_ORDER_HUB_PRINT_QUEUE_DELAY_SECONDS', 240);
define('NP_ORDER_HUB_PRINT_QUEUE_RETRY_SECONDS', 60);
define('NP_ORDER_HUB_PRINT_QUEUE_MAX_ATTEMPTS', 20);
define('NP_ORDER_HUB_PRINT_AGENT_TOKEN_OPTION', 'np_order_hub_print_agent_token');
define('NP_ORDER_HUB_PRINT_AGENT_CLAIM_TIMEOUT_SECONDS', 300);
define('NP_ORDER_HUB_PRINT_AGENT_HEARTBEAT_OPTION', 'np_order_hub_print_agent_heartbeat');
define('NP_ORDER_HUB_PRODUCTION_ERROR_SOURCE_QR', 'qr');

function np_order_hub_tempnam($prefix = 'np-order-hub') {
    $prefix = (string) $prefix;
    if ($prefix === '') {
        $prefix = 'np-order-hub';
    }

    if (function_exists('wp_tempnam')) {
        $tmp = wp_tempnam($prefix);
        if (is_string($tmp) && $tmp !== '') {
            return $tmp;
        }
    }

    if (defined('ABSPATH')) {
        $file_api = ABSPATH . 'wp-admin/includes/file.php';
        if (is_readable($file_api)) {
            require_once $file_api;
        }
    }

    if (function_exists('wp_tempnam')) {
        $tmp = wp_tempnam($prefix);
        if (is_string($tmp) && $tmp !== '') {
            return $tmp;
        }
    }

    $tmp_dir = function_exists('get_temp_dir') ? get_temp_dir() : sys_get_temp_dir();
    if (!is_string($tmp_dir) || $tmp_dir === '' || !is_dir($tmp_dir) || !is_writable($tmp_dir)) {
        $tmp_dir = sys_get_temp_dir();
    }

    $safe_prefix = preg_replace('/[^A-Za-z0-9_-]/', '-', $prefix);
    if (!is_string($safe_prefix) || $safe_prefix === '' || $safe_prefix === '-') {
        $safe_prefix = 'npoh-';
    }
    $safe_prefix = substr($safe_prefix, 0, 20);

    $tmp = @tempnam($tmp_dir, $safe_prefix);
    if (!is_string($tmp) || $tmp === '') {
        return false;
    }
    return $tmp;
}

function np_order_hub_table_name() {
    global $wpdb;
    return $wpdb->prefix . 'np_order_hub_orders';
}

function np_order_hub_production_error_table_name() {
    global $wpdb;
    return $wpdb->prefix . 'np_order_hub_production_errors';
}

function np_order_hub_activate() {
    global $wpdb;
    $table = np_order_hub_table_name();
    $production_table = np_order_hub_production_error_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        store_key VARCHAR(100) NOT NULL,
        store_name VARCHAR(200) NOT NULL,
        store_url VARCHAR(255) NOT NULL,
        order_id BIGINT(20) UNSIGNED NOT NULL,
        order_number VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        currency VARCHAR(10) NOT NULL,
        total DECIMAL(18,4) NOT NULL DEFAULT 0,
        date_created_gmt DATETIME NULL,
        date_modified_gmt DATETIME NULL,
        order_admin_url TEXT NULL,
        payload LONGTEXT NULL,
        created_at_gmt DATETIME NOT NULL,
        updated_at_gmt DATETIME NOT NULL,
        PRIMARY KEY  (id),
        UNIQUE KEY store_order (store_key, order_id),
        KEY store_key (store_key),
        KEY status (status),
        KEY date_created_gmt (date_created_gmt)
    ) $charset_collate;";

	    $production_sql = "CREATE TABLE $production_table (
	        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
	        store_key VARCHAR(100) NOT NULL,
	        store_name VARCHAR(200) NOT NULL,
	        store_url VARCHAR(255) NOT NULL,
        product_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
        variation_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
        product_name VARCHAR(255) NOT NULL,
        size_label VARCHAR(191) NOT NULL,
        sku VARCHAR(100) NOT NULL,
        quantity INT(10) UNSIGNED NOT NULL DEFAULT 1,
        unit_cost DECIMAL(18,4) NOT NULL DEFAULT 0,
        total_cost DECIMAL(18,4) NOT NULL DEFAULT 0,
        currency VARCHAR(10) NOT NULL,
	        stock_before DECIMAL(18,4) NULL,
	        stock_after DECIMAL(18,4) NULL,
	        source VARCHAR(40) NOT NULL DEFAULT '',
	        error_type VARCHAR(40) NOT NULL DEFAULT 'trykkfeil',
	        note TEXT NULL,
	        payload LONGTEXT NULL,
	        created_at_gmt DATETIME NOT NULL,
	        updated_at_gmt DATETIME NOT NULL,
	        PRIMARY KEY (id),
	        KEY store_key (store_key),
	        KEY created_at_gmt (created_at_gmt),
	        KEY product_id (product_id),
	        KEY error_type (error_type)
	    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
    dbDelta($production_sql);
}

$np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;
register_activation_hook($np_order_hub_main_file, 'np_order_hub_activate');

function np_order_hub_ensure_production_error_table() {
    static $checked = false;
    if ($checked) {
        return;
    }
    $checked = true;

    global $wpdb;
    if (!isset($wpdb) || !($wpdb instanceof wpdb)) {
        return;
    }
    $table = np_order_hub_production_error_table_name();
    if ($table === '') {
        return;
    }
    $exists = (string) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
	    if ($exists !== $table) {
	        np_order_hub_activate();
	        $exists = (string) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
	        if ($exists !== $table) {
	            return;
	        }
	    }

	    $table_sql = str_replace('`', '``', $table);
	    $has_error_type = (string) $wpdb->get_var("SHOW COLUMNS FROM `{$table_sql}` LIKE 'error_type'");
	    if ($has_error_type === '') {
	        $wpdb->query("ALTER TABLE `{$table_sql}` ADD COLUMN error_type VARCHAR(40) NOT NULL DEFAULT 'trykkfeil' AFTER source");
	    }
	    $has_error_type_index = (string) $wpdb->get_var("SHOW INDEX FROM `{$table_sql}` WHERE Key_name = 'error_type'");
	    if ($has_error_type_index === '') {
	        $wpdb->query("ALTER TABLE `{$table_sql}` ADD KEY error_type (error_type)");
	    }
}

function np_order_hub_get_production_error_type_options() {
	return array(
		'trykkfeil' => 'Trykkfeil',
		'leverandorfeil' => 'Feil fra leverandør',
	);
}

function np_order_hub_normalize_production_error_type($value) {
	$value = sanitize_key((string) $value);
	$options = np_order_hub_get_production_error_type_options();
	if (isset($options[$value])) {
		return $value;
	}
	return 'trykkfeil';
}

function np_order_hub_get_production_error_type_label($value) {
	$options = np_order_hub_get_production_error_type_options();
	$value = np_order_hub_normalize_production_error_type($value);
	return isset($options[$value]) ? $options[$value] : $options['trykkfeil'];
}

function np_order_hub_get_stores() {
    $stores = get_option(NP_ORDER_HUB_OPTION_STORES, array());
    return is_array($stores) ? $stores : array();
}

function np_order_hub_get_store_by_key($store_key) {
    $store_key = sanitize_key((string) $store_key);
    if ($store_key === '') {
        return null;
    }
    $stores = np_order_hub_get_stores();
    if (isset($stores[$store_key]) && is_array($stores[$store_key])) {
        return $stores[$store_key];
    }
    return null;
}

function np_order_hub_save_stores($stores) {
    update_option(NP_ORDER_HUB_OPTION_STORES, $stores);
}

function np_order_hub_get_connector_setup_key($generate_if_missing = false) {
    $key = trim((string) get_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, ''));
    if ($key === '' && $generate_if_missing) {
        $key = wp_generate_password(48, false, false);
        update_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, $key, false);
    }
    return $key;
}
