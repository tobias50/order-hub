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
define('NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION', 'np_order_hub_help_scout_token');
define('NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION', 'np_order_hub_help_scout_mailbox');
define('NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION', 'np_order_hub_help_scout_default_status');
define('NP_ORDER_HUB_HELP_SCOUT_USER_OPTION', 'np_order_hub_help_scout_user');
define('NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION', 'np_order_hub_help_scout_client_id');
define('NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION', 'np_order_hub_help_scout_client_secret');
define('NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION', 'np_order_hub_help_scout_refresh_token');
define('NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION', 'np_order_hub_help_scout_expires_at');
define('NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION', 'np_order_hub_connector_setup_key');

function np_order_hub_table_name() {
    global $wpdb;
    return $wpdb->prefix . 'np_order_hub_orders';
}

function np_order_hub_activate() {
    global $wpdb;
    $table = np_order_hub_table_name();
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

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}

register_activation_hook(__FILE__, 'np_order_hub_activate');

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

function np_order_hub_store_upsert($data) {
    $stores = np_order_hub_get_stores();

    $key = sanitize_key((string) ($data['key'] ?? ''));
    $name = sanitize_text_field((string) ($data['name'] ?? ''));
    $url = esc_url_raw((string) ($data['url'] ?? ''));
    $secret = trim((string) ($data['secret'] ?? ''));
    $token = sanitize_text_field((string) ($data['token'] ?? ''));
    $consumer_key = sanitize_text_field((string) ($data['consumer_key'] ?? ''));
    $consumer_secret = sanitize_text_field((string) ($data['consumer_secret'] ?? ''));
    $packing_slip_url = np_order_hub_sanitize_url_template((string) ($data['packing_slip_url'] ?? ''));
    $order_url_type = sanitize_key((string) ($data['order_url_type'] ?? NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE));
    $order_url_type = $order_url_type === 'hpos' ? 'hpos' : 'legacy';
    $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($data['delivery_bucket'] ?? 'standard'));
    $switch_date_raw = sanitize_text_field((string) ($data['delivery_bucket_switch_date'] ?? ''));
    $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
    $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($data['delivery_bucket_after'] ?? ''));

    if ($key === '' || $name === '' || $url === '' || $secret === '') {
        return new WP_Error('missing_fields', 'Store key, name, url and secret are required.');
    }

    $stores[$key] = array(
        'key' => $key,
        'name' => $name,
        'url' => $url,
        'normalized_url' => np_order_hub_normalize_store_url($url),
        'secret' => $secret,
        'token' => $token,
        'consumer_key' => $consumer_key,
        'consumer_secret' => $consumer_secret,
        'packing_slip_url' => $packing_slip_url,
        'order_url_type' => $order_url_type,
        'delivery_bucket' => $delivery_bucket,
        'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
        'delivery_bucket_after' => $delivery_bucket_after,
    );

    np_order_hub_save_stores($stores);
    return $stores[$key];
}

function np_order_hub_rest_store_connect(WP_REST_Request $request) {
    $configured_key = np_order_hub_get_connector_setup_key(false);
    if ($configured_key === '') {
        return new WP_REST_Response(array('error' => 'setup_key_missing'), 503);
    }

    $provided_key = trim((string) $request->get_header('x-np-order-hub-setup-key'));
    if ($provided_key === '') {
        $provided_key = trim((string) $request->get_param('setup_key'));
    }
    if ($provided_key === '' || !hash_equals($configured_key, $provided_key)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }

    $body = json_decode((string) $request->get_body(), true);
    $payload = is_array($body) ? $body : array();
    if (empty($payload)) {
        $payload = $request->get_params();
    }

    $upsert = np_order_hub_store_upsert($payload);
    if (is_wp_error($upsert)) {
        return new WP_REST_Response(array('error' => $upsert->get_error_message()), 400);
    }

    return new WP_REST_Response(array(
        'ok' => true,
        'store' => $upsert,
    ), 200);
}

function np_order_hub_normalize_store_url($url) {
    $url = trim((string) $url);
    if ($url === '') {
        return '';
    }
    $parsed = wp_parse_url($url);
    if (empty($parsed['host'])) {
        return '';
    }
    $host = strtolower($parsed['host']);
    $path = isset($parsed['path']) ? '/' . trim($parsed['path'], '/') : '';
    return rtrim($host . $path, '/');
}

function np_order_hub_find_store_by_url($stores, $source_url) {
    $normalized = np_order_hub_normalize_store_url($source_url);
    if ($normalized === '') {
        return null;
    }
    foreach ($stores as $store) {
        if (!is_array($store) || empty($store['normalized_url'])) {
            continue;
        }
        if ($store['normalized_url'] === $normalized) {
            return $store;
        }
    }
    return null;
}

function np_order_hub_verify_signature($body, $signature, $secret) {
    if ($signature === '' || $secret === '') {
        return false;
    }
    $expected = base64_encode(hash_hmac('sha256', $body, $secret, true));
    return hash_equals($expected, $signature);
}

function np_order_hub_parse_datetime_gmt($primary, $fallback) {
    $date = $primary ? $primary : $fallback;
    $date = is_string($date) ? trim($date) : '';
    if ($date === '') {
        return '';
    }
    $timestamp = strtotime($date);
    if (!$timestamp) {
        return '';
    }
    return gmdate('Y-m-d H:i:s', $timestamp);
}

function np_order_hub_build_admin_base_url($store_url) {
    $store_url = trim((string) $store_url);
    if ($store_url === '') {
        return '';
    }
    $parsed = wp_parse_url($store_url);
    if (empty($parsed['host'])) {
        return '';
    }
    $scheme = isset($parsed['scheme']) ? $parsed['scheme'] : 'https';
    $host = $parsed['host'];
    $path = isset($parsed['path']) ? trim($parsed['path'], '/') : '';
    $base = $scheme . '://' . $host;
    if ($path !== '') {
        $base .= '/' . $path;
    }
    return trailingslashit($base) . 'wp-admin/';
}

function np_order_hub_build_admin_order_url($store, $order_id) {
    if (!is_array($store) || empty($store['url']) || !$order_id) {
        return '';
    }
    $admin_base = np_order_hub_build_admin_base_url($store['url']);
    if ($admin_base === '') {
        return '';
    }
    $type = isset($store['order_url_type']) ? $store['order_url_type'] : NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE;
    $type = $type === 'hpos' ? 'hpos' : 'legacy';
    if ($type === 'hpos') {
        return $admin_base . 'admin.php?page=wc-orders&action=edit&id=' . (int) $order_id;
    }
    return $admin_base . 'post.php?post=' . (int) $order_id . '&action=edit';
}

function np_order_hub_sanitize_url_template($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }
    $value = wp_strip_all_tags($value);
    return preg_replace('/\s+/', '', $value);
}

function np_order_hub_parse_numeric_value($value) {
    if ($value === null || $value === '') {
        return null;
    }
    if (is_string($value)) {
        $value = trim($value);
        $value = str_replace(' ', '', $value);
        $value = str_replace(',', '.', $value);
        $value = preg_replace('/[^0-9\.\-]/', '', $value);
    }
    if ($value === '' || !is_numeric($value)) {
        return null;
    }
    return (float) $value;
}

function np_order_hub_build_site_base_url($store_url) {
    $store_url = trim((string) $store_url);
    if ($store_url === '') {
        return '';
    }
    $parsed = wp_parse_url($store_url);
    if (empty($parsed['host'])) {
        return '';
    }
    $scheme = isset($parsed['scheme']) ? $parsed['scheme'] : 'https';
    $host = $parsed['host'];
    $path = isset($parsed['path']) ? trim($parsed['path'], '/') : '';
    $base = $scheme . '://' . $host;
    if ($path !== '') {
        $base .= '/' . $path;
    }
    return trailingslashit($base);
}

function np_order_hub_extract_token_from_url($url) {
    $url = trim((string) $url);
    if ($url === '') {
        return '';
    }
    $parsed = wp_parse_url($url);
    if (empty($parsed['query'])) {
        return '';
    }
    parse_str($parsed['query'], $params);
    foreach (array('token', 'access_key') as $key) {
        if (empty($params[$key])) {
            continue;
        }
        $value = trim((string) $params[$key]);
        if ($value === '' || $value === '{token}' || $value === '{access_key}') {
            continue;
        }
        return sanitize_text_field($value);
    }
    return '';
}

function np_order_hub_get_store_token($store) {
    if (!is_array($store)) {
        return '';
    }
    $token = '';
    if (!empty($store['token'])) {
        $token = trim((string) $store['token']);
    }
    if ($token === '' && !empty($store['packing_slip_url'])) {
        $token = np_order_hub_extract_token_from_url($store['packing_slip_url']);
    }
    return $token !== '' ? $token : '';
}

function np_order_hub_build_store_api_url($store, $endpoint) {
    if (!is_array($store) || empty($store['url'])) {
        return '';
    }
    $base = np_order_hub_build_site_base_url($store['url']);
    if ($base === '') {
        return '';
    }
    $endpoint = ltrim((string) $endpoint, '/');
    if ($endpoint === '') {
        return '';
    }
    return $base . 'wp-json/np-order-hub/v1/' . $endpoint;
}

function np_order_hub_build_packing_slips_url($store, $order_ids) {
    if (!is_array($order_ids)) {
        $order_ids = array($order_ids);
    }
    $order_ids = array_map('absint', $order_ids);
    $order_ids = array_filter($order_ids, function ($value) {
        return $value > 0;
    });
    if (empty($order_ids)) {
        return '';
    }
    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return '';
    }
    $endpoint = np_order_hub_build_store_api_url($store, 'packing-slips');
    if ($endpoint === '') {
        return '';
    }
    return add_query_arg(array(
        'order_ids' => implode(',', $order_ids),
        'token' => $token,
    ), $endpoint);
}

function np_order_hub_build_packing_slip_url($store, $order_id, $order_number, $payload = null) {
    if (!is_array($store)) {
        return '';
    }

    $template = '';
    if (!empty($store['packing_slip_url'])) {
        $template = (string) $store['packing_slip_url'];
    }
    $template = trim($template);
    $token = np_order_hub_get_store_token($store);

    $payload_data = null;
    if (is_array($payload)) {
        $payload_data = $payload;
    } elseif (is_string($payload) && $payload !== '') {
        $decoded = json_decode($payload, true);
        if (is_array($decoded)) {
            $payload_data = $decoded;
        }
    }

    $access_key = '';
    if (is_array($payload_data)) {
        $access_key = np_order_hub_extract_access_key($payload_data);
    }

    $has_token_placeholder = strpos($template, '{token}') !== false;
    $has_access_placeholder = strpos($template, '{access_key}') !== false;
    $use_store_token = $token !== '' && ($has_token_placeholder || ($has_access_placeholder && strpos($template, 'np-order-hub') !== false));
    if ($access_key === '' && $use_store_token) {
        $access_key = $token;
    }

    if ($template !== '') {
        if (($has_access_placeholder && $access_key === '') || ($has_token_placeholder && $token === '')) {
            $direct = is_array($payload_data) ? np_order_hub_extract_packing_slip_url($payload_data) : '';
            if ($direct !== '') {
                return $direct;
            }
            return '';
        }
        $url = str_replace(
            array('{order_id}', '{order_number}', '{access_key}', '{token}'),
            array((int) $order_id, (string) $order_number, rawurlencode((string) $access_key), rawurlencode((string) $token)),
            $template
        );
        if (strpos($url, '://') !== false) {
            return $url;
        }
        if (strpos($url, '/') === 0) {
            $base = np_order_hub_build_site_base_url(isset($store['url']) ? $store['url'] : '');
            if ($base !== '') {
                return rtrim($base, '/') . $url;
            }
        }
        return $url;
    }

    if ($token !== '') {
        $endpoint = np_order_hub_build_store_api_url($store, 'packing-slip');
        if ($endpoint !== '') {
            return add_query_arg(array(
                'order_id' => (int) $order_id,
                'token' => $token,
            ), $endpoint);
        }
    }

    if (is_array($payload_data)) {
        return np_order_hub_extract_packing_slip_url($payload_data);
    }
    return '';
}

function np_order_hub_extract_packing_slip_url($payload) {
    if (!is_array($payload)) {
        return '';
    }
    if (empty($payload['np_wpo_packing_slip_url'])) {
        return '';
    }
    $url = esc_url_raw((string) $payload['np_wpo_packing_slip_url']);
    return $url;
}

function np_order_hub_extract_access_key($payload) {
    if (!is_array($payload)) {
        return '';
    }
    if (!empty($payload['np_wpo_packing_slip_url'])) {
        $parsed = wp_parse_url((string) $payload['np_wpo_packing_slip_url']);
        if (!empty($parsed['query'])) {
            parse_str($parsed['query'], $params);
            if (!empty($params['access_key'])) {
                return sanitize_text_field((string) $params['access_key']);
            }
        }
    }
    $candidates = array(
        'np_wpo_access_key',
        'wpo_wcpdf_access_key',
        'wcpdf_access_key',
        'access_key',
    );
    foreach ($candidates as $key) {
        if (!empty($payload[$key])) {
            return sanitize_text_field((string) $payload[$key]);
        }
    }
    if (!empty($payload['meta_data']) && is_array($payload['meta_data'])) {
        foreach ($payload['meta_data'] as $meta) {
            if (!is_array($meta) || empty($meta['key'])) {
                continue;
            }
            $meta_key = sanitize_key((string) $meta['key']);
            if (in_array($meta_key, array('np_wpo_access_key', 'wpo_wcpdf_access_key', 'wcpdf_access_key'), true)) {
                if (isset($meta['value'])) {
                    return sanitize_text_field((string) $meta['value']);
                }
            }
        }
    }
    return '';
}

function np_order_hub_pdf_bytes_look_valid($bytes) {
    if (!is_string($bytes) || $bytes === '') {
        return false;
    }
    $pos = strpos($bytes, '%PDF-');
    if ($pos === false) {
        return false;
    }
    return $pos < 1024;
}

function np_order_hub_fetch_packing_slips_pdf($url) {
    if ($url === '') {
        return new WP_Error('packing_slips_missing_url', 'Packing slip URL missing.');
    }
    $response = wp_remote_get($url, array(
        'timeout' => 45,
        'redirection' => 3,
        'headers' => array(
            'Accept' => 'application/pdf',
        ),
    ));
    if (is_wp_error($response)) {
        return $response;
    }
    $code = (int) wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        return new WP_Error('packing_slips_http_' . $code, 'Packing slip request failed (HTTP ' . $code . ').');
    }
    if (!np_order_hub_pdf_bytes_look_valid($body)) {
        $content_type = wp_remote_retrieve_header($response, 'content-type');
        $message = 'Packing slip response was not a PDF.';
        if (is_string($content_type) && $content_type !== '') {
            $message .= ' (' . $content_type . ')';
        }
        return new WP_Error('packing_slips_invalid_pdf', $message);
    }
    return $body;
}

function np_order_hub_is_exec_function_enabled($name) {
    if (!is_string($name) || $name === '') {
        return false;
    }
    if (!function_exists($name)) {
        return false;
    }
    $disabled = ini_get('disable_functions');
    if (is_string($disabled) && $disabled !== '') {
        $disabled_list = array_map('trim', explode(',', $disabled));
        if (in_array($name, $disabled_list, true)) {
            return false;
        }
    }
    return is_callable($name);
}

function np_order_hub_run_command($cmd, &$exit_code = null, &$output = '') {
    $exit_code = null;
    $output = '';
    if (!is_string($cmd) || $cmd === '') {
        return false;
    }

    if (np_order_hub_is_exec_function_enabled('proc_open')) {
        $descriptors = array(
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($process)) {
            $stdout = isset($pipes[1]) ? stream_get_contents($pipes[1]) : '';
            $stderr = isset($pipes[2]) ? stream_get_contents($pipes[2]) : '';
            if (isset($pipes[1]) && is_resource($pipes[1])) {
                fclose($pipes[1]);
            }
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                fclose($pipes[2]);
            }
            $exit_code = proc_close($process);
            $output = trim($stdout . "\n" . $stderr);
            return true;
        }
    }

    if (np_order_hub_is_exec_function_enabled('exec')) {
        $lines = array();
        $code = 0;
        @exec($cmd . ' 2>&1', $lines, $code);
        $exit_code = $code;
        $output = trim(implode("\n", $lines));
        return true;
    }

    if (np_order_hub_is_exec_function_enabled('shell_exec')) {
        $output = trim((string) @shell_exec($cmd . ' 2>&1'));
        $exit_code = null;
        return true;
    }

    return false;
}

function np_order_hub_find_binary($name, $filter_name, $env_name, $candidates = array()) {
    $path = apply_filters($filter_name, '');
    if (is_string($path) && $path !== '' && is_file($path)) {
        return $path;
    }
    if (is_string($env_name) && $env_name !== '') {
        $env = getenv($env_name);
        if (is_string($env) && $env !== '' && is_file($env)) {
            return $env;
        }
    }
    if (np_order_hub_is_exec_function_enabled('shell_exec')) {
        $cmd = 'command -v ' . escapeshellarg($name);
        $found = trim((string) @shell_exec($cmd . ' 2>/dev/null'));
        if ($found !== '' && is_file($found)) {
            return $found;
        }
    }
    foreach ($candidates as $candidate) {
        if (is_string($candidate) && $candidate !== '' && is_file($candidate)) {
            return $candidate;
        }
    }
    return '';
}

function np_order_hub_require_fpdi() {
    if (class_exists('\\setasign\\Fpdi\\Fpdi')) {
        return true;
    }
    $base = __DIR__ . '/vendor/setasign';
    $fpdf = $base . '/fpdf/fpdf.php';
    if (is_file($fpdf) && !class_exists('FPDF')) {
        require_once $fpdf;
    }
    $fpdi_base = $base . '/fpdi/src/';
    if (!is_dir($fpdi_base)) {
        return false;
    }
    static $registered = false;
    if (!$registered) {
        $registered = true;
        $prefix = 'setasign\\Fpdi\\';
        $base_dir = $fpdi_base;
        spl_autoload_register(function ($class) use ($prefix, $base_dir) {
            if (strpos($class, $prefix) !== 0) {
                return;
            }
            $relative = substr($class, strlen($prefix));
            if ($relative === '') {
                return;
            }
            $file = $base_dir . str_replace('\\', '/', $relative) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        });
    }
    return class_exists('\\setasign\\Fpdi\\Fpdi');
}

function np_order_hub_merge_pdfs_fpdi($pdf_paths) {
    if (!np_order_hub_require_fpdi()) {
        return new WP_Error('fpdi_missing', 'FPDI library missing.');
    }
    if (!class_exists('\\setasign\\Fpdi\\Fpdi')) {
        return new WP_Error('fpdi_missing', 'FPDI class not available.');
    }
    try {
        $pdf = new \setasign\Fpdi\Fpdi();
        foreach ($pdf_paths as $path) {
            if (!is_file($path)) {
                continue;
            }
            $page_count = $pdf->setSourceFile($path);
            if (!$page_count || $page_count < 1) {
                continue;
            }
            for ($page_no = 1; $page_no <= $page_count; $page_no++) {
                $tpl_id = $pdf->importPage($page_no);
                $size = $pdf->getTemplateSize($tpl_id);
                $orientation = ($size['width'] > $size['height']) ? 'L' : 'P';
                $pdf->AddPage($orientation, array($size['width'], $size['height']));
                $pdf->useTemplate($tpl_id);
            }
        }
        $out = wp_tempnam('packing-slips-merge');
        if (!$out) {
            return new WP_Error('fpdi_temp_failed', 'Could not create temp file for FPDI merge.');
        }
        $out .= '.pdf';
        $pdf->Output('F', $out);
        if (is_file($out) && filesize($out) > 1000) {
            return $out;
        }
        if (is_file($out)) {
            @unlink($out);
        }
        return new WP_Error('fpdi_merge_failed', 'FPDI did not create output.');
    } catch (Throwable $e) {
        return new WP_Error('fpdi_exception', $e->getMessage());
    }
}

function np_order_hub_merge_pdfs($pdf_paths) {
    if (empty($pdf_paths)) {
        return new WP_Error('empty_pdfs', 'No PDFs to merge.');
    }
    $last_error = '';

    $qpdf = np_order_hub_find_binary(
        'qpdf',
        'np_order_hub_qpdf_path',
        'NP_ORDER_HUB_QPDF_PATH',
        array('/usr/bin/qpdf', '/usr/local/bin/qpdf', '/opt/homebrew/bin/qpdf')
    );
    if ($qpdf !== '') {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellarg($qpdf) . ' --empty --pages';
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' -- ' . escapeshellarg($out);
            $exit = null;
            $output = '';
            $ran = np_order_hub_run_command($cmd, $exit, $output);
            if ($ran && is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (!$ran) {
                $last_error = 'Could not execute qpdf.';
            } elseif ($output !== '') {
                $last_error = 'qpdf error: ' . $output;
            } elseif ($exit !== null && $exit !== 0) {
                $last_error = 'qpdf exited with code ' . $exit . '.';
            } else {
                $last_error = 'qpdf did not create output.';
            }
            if (is_file($out)) {
                @unlink($out);
            }
        } else {
            $last_error = 'Could not create temp file for qpdf.';
        }
    }

    $gs = np_order_hub_find_binary(
        'gs',
        'np_order_hub_gs_path',
        'NP_ORDER_HUB_GS_PATH',
        array('/usr/bin/gs', '/usr/local/bin/gs', '/opt/homebrew/bin/gs')
    );
    if ($gs !== '') {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellarg($gs) . ' -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=' . escapeshellarg($out);
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $exit = null;
            $output = '';
            $ran = np_order_hub_run_command($cmd, $exit, $output);
            if ($ran && is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (!$ran && $last_error === '') {
                $last_error = 'Could not execute ghostscript.';
            } elseif ($output !== '' && $last_error === '') {
                $last_error = 'ghostscript error: ' . $output;
            } elseif ($exit !== null && $exit !== 0 && $last_error === '') {
                $last_error = 'ghostscript exited with code ' . $exit . '.';
            } elseif ($last_error === '') {
                $last_error = 'ghostscript did not create output.';
            }
            if (is_file($out)) {
                @unlink($out);
            }
        } elseif ($last_error === '') {
            $last_error = 'Could not create temp file for ghostscript.';
        }
    }

    if ($last_error !== '') {
        $fpdi = np_order_hub_merge_pdfs_fpdi($pdf_paths);
        if (!is_wp_error($fpdi)) {
            return $fpdi;
        }
        return new WP_Error('merge_unavailable', $last_error . ' ' . $fpdi->get_error_message());
    }
    $fpdi = np_order_hub_merge_pdfs_fpdi($pdf_paths);
    if (!is_wp_error($fpdi)) {
        return $fpdi;
    }
    return new WP_Error('merge_unavailable', $fpdi->get_error_message());
}

function np_order_hub_build_packing_slips_bundle($groups) {
    if (empty($groups) || !is_array($groups)) {
        return new WP_Error('missing_groups', 'No stores selected.');
    }
    $timestamp = gmdate('Ymd-His');
    $pdf_files = array();
    $used_names = array();
    $preview_links = array();
    $errors = array();

    foreach ($groups as $store_key => $group) {
        $store_key = sanitize_key((string) $store_key);
        $store = isset($group['store']) && is_array($group['store']) ? $group['store'] : null;
        $order_ids = isset($group['order_ids']) && is_array($group['order_ids']) ? $group['order_ids'] : array();
        $order_ids = array_values(array_filter(array_map('absint', $order_ids), function ($value) {
            return $value > 0;
        }));
        if ($store_key === '' || !$store || empty($order_ids)) {
            continue;
        }
        $bulk_url = np_order_hub_build_packing_slips_url($store, $order_ids);
        if ($bulk_url === '') {
            $errors[] = 'Packing slip bulk URL is not configured for store ' . ($store['name'] ?? $store_key) . '.';
            continue;
        }
        $preview_links[] = array(
            'label' => isset($store['name']) && is_string($store['name']) && $store['name'] !== '' ? $store['name'] : $store_key,
            'url' => $bulk_url,
            'count' => count($order_ids),
        );
        $pdf_bytes = np_order_hub_fetch_packing_slips_pdf($bulk_url);
        if (is_wp_error($pdf_bytes)) {
            $errors[] = 'Packing slips failed for store ' . ($store['name'] ?? $store_key) . ': ' . $pdf_bytes->get_error_message();
            continue;
        }
        $tmp = wp_tempnam('packing-slips-' . $store_key);
        if (!$tmp) {
            $errors[] = 'Could not create temporary file for store ' . ($store['name'] ?? $store_key) . '.';
            continue;
        }
        $path = $tmp . '.pdf';
        @rename($tmp, $path);
        file_put_contents($path, $pdf_bytes);

        $label = isset($store['name']) && is_string($store['name']) && $store['name'] !== '' ? $store['name'] : $store_key;
        $label = sanitize_file_name($label);
        if ($label === '') {
            $label = $store_key !== '' ? $store_key : 'store';
        }
        $base_name = 'packing-slips-' . $label;
        $final_name = $base_name;
        $suffix = 2;
        while (isset($used_names[$final_name])) {
            $final_name = $base_name . '-' . $suffix;
            $suffix++;
        }
        $used_names[$final_name] = true;

        $pdf_files[] = array(
            'path' => $path,
            'name' => $final_name . '.pdf',
        );
    }

    if (!empty($errors)) {
        foreach ($pdf_files as $file) {
            if (!empty($file['path']) && is_file($file['path'])) {
                @unlink($file['path']);
            }
        }
        return new WP_Error('packing_slips_failed', implode(' ', $errors));
    }

    if (empty($pdf_files)) {
        return new WP_Error('packing_slips_empty', 'No packing slips could be generated.');
    }

    $pdf_paths = array_map(function ($file) {
        return $file['path'];
    }, $pdf_files);

    if (count($pdf_paths) > 1) {
        $merged = np_order_hub_merge_pdfs($pdf_paths);
        foreach ($pdf_paths as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
        if (!is_wp_error($merged)) {
            return array(
                'path' => $merged,
                'filename' => 'packing-slips-' . $timestamp . '.pdf',
                'content_type' => 'application/pdf',
                'inline' => true,
            );
        }
        return array(
            'preview_links' => $preview_links,
            'merge_error' => $merged instanceof WP_Error ? $merged->get_error_message() : '',
        );
    }

    return array(
        'path' => $pdf_paths[0],
        'filename' => 'packing-slips-' . $timestamp . '.pdf',
        'content_type' => 'application/pdf',
        'inline' => true,
    );
}

function np_order_hub_send_download($payload) {
    if (!is_array($payload) || empty($payload['path'])) {
        return;
    }
    $path = (string) $payload['path'];
    if (!is_file($path)) {
        return;
    }
    $filename = isset($payload['filename']) ? sanitize_file_name((string) $payload['filename']) : basename($path);
    if ($filename === '') {
        $filename = basename($path);
    }
    $content_type = isset($payload['content_type']) ? (string) $payload['content_type'] : 'application/octet-stream';
    $inline = !empty($payload['inline']);

    while (ob_get_level()) {
        @ob_end_clean();
    }
    nocache_headers();
    header('Content-Type: ' . $content_type);
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $filename . '"');
    if (is_file($path)) {
        $size = filesize($path);
        if ($size !== false) {
            header('Content-Length: ' . $size);
        }
    }
    readfile($path);
    @unlink($path);
    exit;
}

function np_order_hub_send_packing_slips_preview_page($links, $merge_error = '') {
    if (empty($links) || !is_array($links)) {
        return;
    }
    while (ob_get_level()) {
        @ob_end_clean();
    }
    nocache_headers();
    header('Content-Type: text/html; charset=' . get_bloginfo('charset'));
    echo '<!doctype html><html><head><meta charset="' . esc_attr(get_bloginfo('charset')) . '">';
    echo '<title>Packing slips preview</title>';
    echo '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;}';
    echo 'h1{margin:0 0 12px;font-size:20px;}';
    echo 'p{margin:0 0 12px;color:#444;}';
    echo 'ul{padding-left:18px;}';
    echo 'li{margin:8px 0;}';
    echo '.btn{display:inline-block;margin:12px 0;padding:8px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px;}';
    echo '</style></head><body>';
    echo '<h1>Packing slips</h1>';
    echo '<p>Kunne ikke slå sammen PDF-ene til ett dokument. Åpne hver butikk i forhåndsvisning:</p>';
    if (is_string($merge_error) && $merge_error !== '') {
        echo '<p style="color:#b32d2e; margin-top:6px;">Feil: ' . esc_html($merge_error) . '</p>';
    }
    echo '<a class="btn" href="#" id="np-open-all">Åpne alle</a>';
    echo '<ul>';
    $urls = array();
    foreach ($links as $link) {
        $label = isset($link['label']) ? (string) $link['label'] : 'Store';
        $count = isset($link['count']) ? (int) $link['count'] : 0;
        $url = isset($link['url']) ? (string) $link['url'] : '';
        if ($url === '') {
            continue;
        }
        $urls[] = $url;
        $label_text = $label;
        if ($count > 0) {
            $label_text .= ' (' . $count . ')';
        }
        echo '<li><a href="' . esc_url($url) . '" target="_blank" rel="noopener noreferrer">' . esc_html($label_text) . '</a></li>';
    }
    echo '</ul>';
    echo '<script>(function(){var links=' . wp_json_encode($urls) . ';';
    echo 'var btn=document.getElementById("np-open-all");';
    echo 'if(btn){btn.addEventListener("click",function(e){e.preventDefault();';
    echo 'links.forEach(function(url){window.open(url,"_blank");});';
    echo '});}})();</script>';
    echo '</body></html>';
    exit;
}

add_action('rest_api_init', 'np_order_hub_register_routes');

function np_order_hub_register_routes() {
    register_rest_route('np-order-hub/v1', '/webhook', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_handle_webhook',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/store-connect', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_rest_store_connect',
        'permission_callback' => '__return_true',
    ));
}

function np_order_hub_handle_webhook(WP_REST_Request $request) {
    $body = $request->get_body();
    $signature = (string) $request->get_header('X-WC-Webhook-Signature');
    $event = strtolower((string) $request->get_header('X-WC-Webhook-Event'));
    $topic = strtolower((string) $request->get_header('X-WC-Webhook-Topic'));
    $store_key = sanitize_key((string) $request->get_param('store'));
    $stores = np_order_hub_get_stores();

    $store = null;
    if ($store_key !== '' && isset($stores[$store_key])) {
        $store = $stores[$store_key];
    }
    if (!$store) {
        $source = (string) $request->get_header('X-WC-Webhook-Source');
        $store = np_order_hub_find_store_by_url($stores, $source);
    }
    if (!$store) {
        return new WP_REST_Response(array('error' => 'unknown_store'), 401);
    }
    if (empty($store['secret'])) {
        return new WP_REST_Response(array('error' => 'missing_secret'), 401);
    }
    if (!np_order_hub_verify_signature($body, $signature, $store['secret'])) {
        return new WP_REST_Response(array('error' => 'bad_signature'), 401);
    }

    $data = json_decode($body, true);
    if (!is_array($data) || empty($data['id'])) {
        return new WP_REST_Response(array('error' => 'bad_payload'), 400);
    }

    if ($event === '' && $topic !== '' && strpos($topic, '.') !== false) {
        $topic_parts = explode('.', $topic, 2);
        if (isset($topic_parts[1])) {
            $event = (string) $topic_parts[1];
        }
    }

    $order_id = absint($data['id']);
    if (in_array($event, array('deleted', 'trashed', 'trash'), true)) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $wpdb->delete($table, array(
            'store_key' => $store['key'],
            'order_id' => $order_id,
        ), array('%s', '%d'));
        return new WP_REST_Response(array('status' => 'deleted'), 200);
    }

    $order_number = isset($data['number']) ? sanitize_text_field((string) $data['number']) : (string) $order_id;
    $status = isset($data['status']) ? sanitize_key((string) $data['status']) : '';
    $currency = isset($data['currency']) ? sanitize_text_field((string) $data['currency']) : '';
    $total_raw = isset($data['total']) ? (string) $data['total'] : '0';
    $total = is_numeric($total_raw) ? (float) $total_raw : 0.0;

    $date_created_gmt = np_order_hub_parse_datetime_gmt(
        isset($data['date_created_gmt']) ? $data['date_created_gmt'] : '',
        isset($data['date_created']) ? $data['date_created'] : ''
    );
    $date_modified_gmt = np_order_hub_parse_datetime_gmt(
        isset($data['date_modified_gmt']) ? $data['date_modified_gmt'] : '',
        isset($data['date_modified']) ? $data['date_modified'] : ''
    );

    $order_admin_url = np_order_hub_build_admin_order_url($store, $order_id);

    global $wpdb;
    $table = np_order_hub_table_name();

    $existing = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT id, payload FROM $table WHERE store_key = %s AND order_id = %d",
            $store['key'],
            $order_id
        ),
        ARRAY_A
    );
    $existing_id = $existing ? (int) $existing['id'] : 0;
    $existing_bucket = $existing ? np_order_hub_extract_delivery_bucket_from_payload_data($existing['payload']) : '';
    $incoming_bucket = np_order_hub_extract_delivery_bucket_from_payload_data($data);
    $store_bucket = np_order_hub_get_active_store_delivery_bucket($store);
    $bucket_to_set = $existing_bucket !== '' ? $existing_bucket : ($incoming_bucket !== '' ? $incoming_bucket : $store_bucket);
    $data[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $bucket_to_set;

    $record = array(
        'store_key' => $store['key'],
        'store_name' => $store['name'],
        'store_url' => $store['url'],
        'order_id' => $order_id,
        'order_number' => $order_number,
        'status' => $status,
        'currency' => $currency,
        'total' => $total,
        'date_created_gmt' => $date_created_gmt !== '' ? $date_created_gmt : null,
        'date_modified_gmt' => $date_modified_gmt !== '' ? $date_modified_gmt : null,
        'order_admin_url' => $order_admin_url,
        'payload' => wp_json_encode($data),
    );

    $now_gmt = current_time('mysql', true);
    if ($existing_id) {
        $record['updated_at_gmt'] = $now_gmt;
        $wpdb->update($table, $record, array('id' => $existing_id));
    } else {
        $record['created_at_gmt'] = $now_gmt;
        $record['updated_at_gmt'] = $now_gmt;
        $wpdb->insert($table, $record);
        np_order_hub_maybe_notify_new_order($store, $order_number, $order_id, $status, $total, $currency);
    }

    return new WP_REST_Response(array('status' => 'ok'), 200);
}

add_action('admin_menu', 'np_order_hub_admin_menu');

function np_order_hub_admin_menu() {
    $capability = 'manage_options';
    add_menu_page(
        'Order Hub',
        'Order Hub',
        $capability,
        'np-order-hub',
        'np_order_hub_orders_page',
        'dashicons-clipboard',
        56
    );
    add_submenu_page('np-order-hub', 'Levering 3-5 dager', 'Levering 3-5 dager', $capability, 'np-order-hub-dashboard', 'np_order_hub_dashboard_page');
    add_submenu_page('np-order-hub', 'Levering til bestemt dato', 'Levering til bestemt dato', $capability, 'np-order-hub-scheduled', 'np_order_hub_dashboard_page');
    add_submenu_page('np-order-hub', 'Omsetning', 'Omsetning', $capability, 'np-order-hub-revenue', 'np_order_hub_revenue_page');
    add_submenu_page('np-order-hub', 'Reklamasjon', 'Reklamasjon', $capability, 'np-order-hub-reklamasjon', 'np_order_hub_reklamasjon_page');
    add_submenu_page('np-order-hub', 'Restordre', 'Restordre', $capability, 'np-order-hub-restordre', 'np_order_hub_restordre_page');
    add_submenu_page('np-order-hub', 'Orders', 'Orders', $capability, 'np-order-hub', 'np_order_hub_orders_page');
    add_submenu_page('np-order-hub', 'Stores', 'Stores', $capability, 'np-order-hub-stores', 'np_order_hub_stores_page');
    add_submenu_page('np-order-hub', 'Varsler', 'Varsler', $capability, 'np-order-hub-notifications', 'np_order_hub_notifications_page');
    add_submenu_page('np-order-hub', 'Help Scout', 'Help Scout', $capability, 'np-order-hub-help-scout', 'np_order_hub_help_scout_page');
    add_submenu_page('np-order-hub', 'Debug', 'Debug', $capability, 'np-order-hub-debug', 'np_order_hub_debug_page');
    add_submenu_page(null, 'Order Details', 'Order Details', $capability, 'np-order-hub-details', 'np_order_hub_order_details_page');
}

function np_order_hub_orders_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    if (!empty($_GET['np_order_hub_deleted'])) {
        echo '<div class="updated"><p>Order removed from hub.</p></div>';
    }
    $table = new NP_Order_Hub_Orders_Table();
    $table->prepare_items();

    echo '<div class="wrap">';
    echo '<h1>Order Hub</h1>';
    echo '<form method="get">';
    echo '<input type="hidden" name="page" value="np-order-hub" />';
    $table->display();
    echo '</form>';
    echo '</div>';
}

function np_order_hub_get_date_gmt_from_input($value, $end_of_day = false) {
    $value = sanitize_text_field((string) $value);
    if ($value === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
        return '';
    }
    $time = $end_of_day ? '23:59:59' : '00:00:00';
    return get_gmt_from_date($value . ' ' . $time);
}

function np_order_hub_get_dashboard_filters($default_status = 'processing') {
    $status_param_exists = array_key_exists('status', $_GET);
    $status_raw = $status_param_exists ? sanitize_key((string) $_GET['status']) : '';
    if (!$status_param_exists) {
        $status = $default_status;
    } elseif ($status_raw === 'all') {
        $status = '';
    } else {
        $status = $status_raw;
    }

    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => $status,
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => isset($_GET['s']) ? sanitize_text_field((string) $_GET['s']) : '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_reklamasjon_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => '',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_restordre_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => 'restordre',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_build_where_clause($filters, &$args, $include_search = true, $include_dates = true) {
    global $wpdb;
    $where = array();

    if (!empty($filters['store'])) {
        $where[] = 'store_key = %s';
        $args[] = $filters['store'];
    }
    if (!empty($filters['status'])) {
        $where[] = 'status = %s';
        $args[] = $filters['status'];
    }
    if ($include_dates) {
        if (!empty($filters['date_from'])) {
            $where[] = 'date_created_gmt >= %s';
            $args[] = $filters['date_from'];
        }
        if (!empty($filters['date_to'])) {
            $where[] = 'date_created_gmt <= %s';
            $args[] = $filters['date_to'];
        }
    }
    if ($include_search && !empty($filters['search'])) {
        $search = $filters['search'];
        $like = '%' . $wpdb->esc_like($search) . '%';
        if (is_numeric($search)) {
            $where[] = '(order_id = %d OR order_number LIKE %s)';
            $args[] = (int) $search;
            $args[] = $like;
        } else {
            $where[] = 'order_number LIKE %s';
            $args[] = $like;
        }
    }

    if (empty($where)) {
        return '';
    }
    return 'WHERE ' . implode(' AND ', $where);
}

function np_order_hub_normalize_delivery_bucket($bucket) {
    $bucket = sanitize_key((string) $bucket);
    return $bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
}

function np_order_hub_normalize_delivery_bucket_optional($bucket) {
    $bucket = sanitize_key((string) $bucket);
    if ($bucket === '') {
        return '';
    }
    return np_order_hub_normalize_delivery_bucket($bucket);
}

function np_order_hub_get_active_store_delivery_bucket($store) {
    $default_bucket = isset($store['delivery_bucket']) ? np_order_hub_normalize_delivery_bucket($store['delivery_bucket']) : 'standard';
    $switch_date = isset($store['delivery_bucket_switch_date']) ? trim((string) $store['delivery_bucket_switch_date']) : '';
    $switch_bucket = isset($store['delivery_bucket_after']) ? np_order_hub_normalize_delivery_bucket_optional($store['delivery_bucket_after']) : '';

    if ($switch_date !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date)) {
        $today = current_time('Y-m-d');
        if ($today >= $switch_date) {
            if ($switch_bucket === '') {
                $switch_bucket = $default_bucket === 'standard' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
            }
            return $switch_bucket;
        }
    }

    return $default_bucket;
}

function np_order_hub_get_delivery_bucket_like() {
    global $wpdb;
    $needle = '"' . NP_ORDER_HUB_DELIVERY_BUCKET_KEY . '":"' . NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED . '"';
    return '%' . $wpdb->esc_like($needle) . '%';
}

function np_order_hub_add_delivery_bucket_where($where, &$args, $bucket) {
    $bucket = np_order_hub_normalize_delivery_bucket($bucket);
    $like = np_order_hub_get_delivery_bucket_like();
    if ($bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED) {
        $clause = 'payload LIKE %s';
        $args[] = $like;
    } else {
        $clause = "(payload NOT LIKE %s OR payload IS NULL OR payload = '')";
        $args[] = $like;
    }
    return $where ? ($where . ' AND ' . $clause) : ('WHERE ' . $clause);
}

function np_order_hub_extract_delivery_bucket_from_payload_data($payload) {
    if (is_string($payload) && $payload !== '') {
        $decoded = json_decode($payload, true);
        if (is_array($decoded)) {
            $payload = $decoded;
        }
    }
    if (!is_array($payload)) {
        return '';
    }
    if (!array_key_exists(NP_ORDER_HUB_DELIVERY_BUCKET_KEY, $payload)) {
        return '';
    }
    return np_order_hub_normalize_delivery_bucket($payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY]);
}

function np_order_hub_query_metric_range($filters, $start_gmt = '', $end_gmt = '', $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, false);

    $range = array();
    if ($start_gmt !== '') {
        $range[] = 'date_created_gmt >= %s';
        $args[] = $start_gmt;
    }
    if ($end_gmt !== '') {
        $range[] = 'date_created_gmt <= %s';
        $args[] = $end_gmt;
    }
    if (!empty($range)) {
        $range_sql = implode(' AND ', $range);
        $where = $where ? ($where . ' AND ' . $range_sql) : ('WHERE ' . $range_sql);
    }

    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);

    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}

function np_order_hub_get_currency_label($filters, $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, false);
    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);
    $currency_where = $where ? ($where . " AND currency <> ''") : "WHERE currency <> ''";
    $sql = "SELECT DISTINCT currency FROM $table $currency_where LIMIT 2";
    $currencies = $args ? $wpdb->get_col($wpdb->prepare($sql, $args)) : $wpdb->get_col($sql);
    if (is_array($currencies) && count($currencies) === 1) {
        return (string) $currencies[0];
    }
    return '';
}

function np_order_hub_get_reklamasjon_like() {
    global $wpdb;
    $needle = '"np_reklamasjon":true';
    return '%' . $wpdb->esc_like($needle) . '%';
}

function np_order_hub_query_reklamasjon_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $reklamasjon_sql = "(payload LIKE %s OR status = %s)";
    $args[] = np_order_hub_get_reklamasjon_like();
    $args[] = 'reklamasjon';
    $where = $where ? ($where . ' AND ' . $reklamasjon_sql) : ('WHERE ' . $reklamasjon_sql);

    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";

    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_reklamasjon_totals($filters, $start_gmt = '', $end_gmt = '') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, false);

    $range = array();
    if ($start_gmt !== '') {
        $range[] = 'date_created_gmt >= %s';
        $args[] = $start_gmt;
    }
    if ($end_gmt !== '') {
        $range[] = 'date_created_gmt <= %s';
        $args[] = $end_gmt;
    }
    if (!empty($range)) {
        $range_sql = implode(' AND ', $range);
        $where = $where ? ($where . ' AND ' . $range_sql) : ('WHERE ' . $range_sql);
    }

    $reklamasjon_sql = "(payload LIKE %s OR status = %s)";
    $args[] = np_order_hub_get_reklamasjon_like();
    $args[] = 'reklamasjon';
    $where = $where ? ($where . ' AND ' . $reklamasjon_sql) : ('WHERE ' . $reklamasjon_sql);

    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}

function np_order_hub_query_reklamasjon_orders($filters, $limit = 100) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $reklamasjon_sql = "(payload LIKE %s OR status = %s)";
    $args[] = np_order_hub_get_reklamasjon_like();
    $args[] = 'reklamasjon';
    $where = $where ? ($where . ' AND ' . $reklamasjon_sql) : ('WHERE ' . $reklamasjon_sql);

    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";

    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}

function np_order_hub_query_restordre_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);

    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";

    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_restordre_totals($filters, $start_gmt = '', $end_gmt = '') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, false);

    $range = array();
    if ($start_gmt !== '') {
        $range[] = 'date_created_gmt >= %s';
        $args[] = $start_gmt;
    }
    if ($end_gmt !== '') {
        $range[] = 'date_created_gmt <= %s';
        $args[] = $end_gmt;
    }
    if (!empty($range)) {
        $range_sql = implode(' AND ', $range);
        $where = $where ? ($where . ' AND ' . $range_sql) : ('WHERE ' . $range_sql);
    }

    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}

function np_order_hub_query_restordre_orders($filters, $limit = 100) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);

    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";

    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}

function np_order_hub_record_is_reklamasjon($record) {
    if (!is_array($record)) {
        return false;
    }
    if (!empty($record['status']) && $record['status'] === 'reklamasjon') {
        return true;
    }
    if (empty($record['payload'])) {
        return false;
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return false;
    }
    if (!empty($payload['np_reklamasjon'])) {
        return true;
    }
    return !empty($payload['np_reklamasjon_source_order']);
}

function np_order_hub_record_delivery_bucket($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return 'standard';
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return 'standard';
    }
    $bucket = isset($payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY]) ? (string) $payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] : '';
    return $bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
}

function np_order_hub_update_delivery_bucket($record, $bucket) {
    if (!is_array($record) || empty($record['id'])) {
        return $record;
    }
    $bucket = np_order_hub_normalize_delivery_bucket($bucket);
    $payload = array();
    if (!empty($record['payload'])) {
        $decoded = json_decode((string) $record['payload'], true);
        if (!is_array($decoded)) {
            return $record;
        }
        $payload = $decoded;
    }
    $payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $bucket;
    $update = array(
        'payload' => wp_json_encode($payload),
        'updated_at_gmt' => current_time('mysql', true),
    );
    global $wpdb;
    $table = np_order_hub_table_name();
    $wpdb->update($table, $update, array('id' => (int) $record['id']));

    $record['payload'] = $update['payload'];
    return $record;
}

function np_order_hub_get_reklamasjon_item_summary($record) {
    $summary = array(
        'lines' => array(),
        'qty' => 0,
    );
    if (!is_array($record) || empty($record['payload'])) {
        return $summary;
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
        return $summary;
    }
    foreach ($payload['line_items'] as $item) {
        if (!is_array($item)) {
            continue;
        }
        $name = isset($item['name']) ? trim((string) $item['name']) : '';
        $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
        if ($qty < 1) {
            continue;
        }
        if ($name === '') {
            $name = 'Item';
        }
        $summary['lines'][] = $name . ' x ' . $qty;
        $summary['qty'] += $qty;
    }
    return $summary;
}

function np_order_hub_count_line_items($payload) {
    if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
        return 0;
    }
    $total = 0;
    foreach ($payload['line_items'] as $item) {
        if (!is_array($item)) {
            continue;
        }
        $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
        if ($qty > 0) {
            $total += $qty;
        }
    }
    return $total;
}

function np_order_hub_get_customer_label($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return '—';
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return '—';
    }
    $billing = isset($payload['billing']) && is_array($payload['billing']) ? $payload['billing'] : array();
    $first = isset($billing['first_name']) ? sanitize_text_field((string) $billing['first_name']) : '';
    $last = isset($billing['last_name']) ? sanitize_text_field((string) $billing['last_name']) : '';
    $name = trim($first . ' ' . $last);
    if ($name === '' && !empty($billing['company'])) {
        $name = sanitize_text_field((string) $billing['company']);
    }
    if ($name === '' && !empty($billing['email'])) {
        $name = sanitize_text_field((string) $billing['email']);
    }
    return $name !== '' ? $name : '—';
}

function np_order_hub_render_order_list_table($orders, $empty_message = 'No orders found.') {
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Order</th>';
    echo '<th>Customer</th>';
    echo '<th>Store</th>';
    echo '<th>Date</th>';
    echo '<th>Status</th>';
    echo '<th>Reklamasjon</th>';
    echo '<th>Total</th>';
    echo '<th>Actions</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($orders)) {
        echo '<tr><td colspan="8">' . esc_html($empty_message) . '</td></tr>';
    } else {
        foreach ($orders as $order) {
            if (!is_array($order)) {
                continue;
            }
            $order_id = isset($order['order_id']) ? (int) $order['order_id'] : 0;
            $order_number = isset($order['order_number']) ? (string) $order['order_number'] : '';
            $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
            $customer_label = np_order_hub_get_customer_label($order);
            $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
            $date_label = '';
            if (!empty($order['date_created_gmt']) && $order['date_created_gmt'] !== '0000-00-00 00:00:00') {
                $date_label = get_date_from_gmt($order['date_created_gmt'], 'd.m.y');
            }
            $status_label = '';
            if (!empty($order['status'])) {
                $status_label = ucwords(str_replace('-', ' ', (string) $order['status']));
            }
            $total_display = np_order_hub_format_money(isset($order['total']) ? (float) $order['total'] : 0.0, isset($order['currency']) ? (string) $order['currency'] : '');
            $is_reklamasjon = np_order_hub_record_is_reklamasjon($order);
            $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $order['id']);
            $open_url = isset($order['order_admin_url']) ? (string) $order['order_admin_url'] : '';
            $store = np_order_hub_get_store_by_key(isset($order['store_key']) ? $order['store_key'] : '');
            $packing_url = np_order_hub_build_packing_slip_url(
                $store,
                $order_id,
                $order_number,
                isset($order['payload']) ? $order['payload'] : null
            );

            echo '<tr>';
            echo '<td>' . esc_html($label) . '</td>';
            echo '<td>' . esc_html($customer_label) . '</td>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html($date_label) . '</td>';
            echo '<td>';
            if ($status_label !== '') {
                echo '<span class="np-order-hub-status">' . esc_html($status_label) . '</span>';
            }
            echo '</td>';
            echo '<td>' . ($is_reklamasjon ? '<span class="np-order-hub-status">Ja</span>' : '—') . '</td>';
            echo '<td>' . esc_html($total_display) . '</td>';
            echo '<td class="np-order-hub-actions">';
            echo '<a class="button button-small" href="' . esc_url($details_url) . '">Details</a>';
            if ($packing_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
            }
            if ($open_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($open_url) . '" target="_blank" rel="noopener">Open order</a>';
            }
            echo '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';
}

function np_order_hub_query_orders($filters, $per_page, $offset, &$total_items, $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, true, true);
    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);

    $count_sql = "SELECT COUNT(*) FROM $table $where";
    $total_items = $args ? (int) $wpdb->get_var($wpdb->prepare($count_sql, $args)) : (int) $wpdb->get_var($count_sql);

    $query_sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d OFFSET %d";
    $query_args = array_merge($args, array((int) $per_page, (int) $offset));
    return $wpdb->get_results($wpdb->prepare($query_sql, $query_args), ARRAY_A);
}

function np_order_hub_get_revenue_excluded_statuses() {
    return array('cancelled', 'refunded', 'reklamasjon');
}

function np_order_hub_get_revenue_allowed_statuses() {
    $all = array_keys(np_order_hub_get_allowed_statuses());
    $excluded = np_order_hub_get_revenue_excluded_statuses();
    return array_values(array_diff($all, $excluded));
}

function np_order_hub_get_historical_revenue() {
    $stored = get_option(NP_ORDER_HUB_HISTORICAL_REVENUE_OPTION, array());
    return is_array($stored) ? $stored : array();
}

function np_order_hub_save_historical_revenue($history) {
    update_option(NP_ORDER_HUB_HISTORICAL_REVENUE_OPTION, is_array($history) ? $history : array());
}

function np_order_hub_get_manual_revenue_seed() {
    $now = current_time('mysql', true);
    return array(
        'ohg' => array(
            'total' => 356918.0,
            'count' => 403,
            'currency' => 'NOK',
            'updated_at_gmt' => $now,
            'manual' => true,
        ),
        'nydalenvgs' => array(
            'total' => 212448.0,
            'count' => 333,
            'currency' => 'NOK',
            'updated_at_gmt' => $now,
            'manual' => true,
        ),
        'askervgs' => array(
            'total' => 313856.0,
            'count' => 566,
            'currency' => 'NOK',
            'updated_at_gmt' => $now,
            'manual' => true,
        ),
    );
}

function np_order_hub_get_manual_revenue() {
    $stored = get_option(NP_ORDER_HUB_MANUAL_REVENUE_OPTION, null);
    $seed = np_order_hub_get_manual_revenue_seed();
    if ($stored === null) {
        if (!empty($seed)) {
            np_order_hub_save_manual_revenue($seed);
            return $seed;
        }
        return array();
    }
    if (!is_array($stored)) {
        $stored = array();
    }
    if (!empty($seed)) {
        $merged = $stored;
        foreach ($seed as $key => $value) {
            if (!isset($merged[$key])) {
                $merged[$key] = $value;
            }
        }
        if ($merged !== $stored) {
            np_order_hub_save_manual_revenue($merged);
            return $merged;
        }
    }
    return $stored;
}

function np_order_hub_save_manual_revenue($manual) {
    update_option(NP_ORDER_HUB_MANUAL_REVENUE_OPTION, is_array($manual) ? $manual : array());
}

function np_order_hub_get_store_first_order_gmt($store_key) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $date = $wpdb->get_var(
        $wpdb->prepare("SELECT MIN(date_created_gmt) FROM $table WHERE store_key = %s", $store_key)
    );
    return is_string($date) ? $date : '';
}

function np_order_hub_build_store_wc_api_url($store, $endpoint) {
    if (!is_array($store) || empty($store['url'])) {
        return '';
    }
    $base = np_order_hub_build_site_base_url($store['url']);
    if ($base === '') {
        return '';
    }
    $endpoint = ltrim((string) $endpoint, '/');
    if ($endpoint === '') {
        return '';
    }
    return $base . 'wp-json/wc/v3/' . $endpoint;
}

function np_order_hub_wc_api_request($store, $endpoint, $params, $timeout = 20) {
    if (!is_array($store) || empty($store['consumer_key']) || empty($store['consumer_secret'])) {
        return new WP_Error('missing_api_credentials', 'Missing WooCommerce API credentials.');
    }
    $url_base = np_order_hub_build_store_wc_api_url($store, $endpoint);
    if ($url_base === '') {
        return new WP_Error('missing_endpoint', 'Missing WooCommerce API endpoint.');
    }
    $params = is_array($params) ? $params : array();
    $consumer_key = (string) $store['consumer_key'];
    $consumer_secret = (string) $store['consumer_secret'];

    $parsed = wp_parse_url($url_base);
    $use_basic = !empty($parsed['scheme']) && strtolower($parsed['scheme']) === 'https';

    $args = array(
        'timeout' => (int) $timeout,
        'headers' => array(),
    );

    $store_key = isset($store['key']) ? sanitize_key((string) $store['key']) : '';
    $store_name = isset($store['name']) ? (string) $store['name'] : '';
    $debug_params = $params;

    if ($use_basic) {
        np_order_hub_revenue_debug_add($store_key, array(
            'event' => 'request',
            'store' => $store_name,
            'endpoint' => $endpoint,
            'auth' => 'basic',
            'url' => $url_base,
            'params' => $debug_params,
        ));
        $args['headers']['Authorization'] = 'Basic ' . base64_encode($consumer_key . ':' . $consumer_secret);
        $url = add_query_arg($params, $url_base);
        $response = wp_remote_get($url, $args);
        if (np_order_hub_revenue_debug_enabled() && !is_wp_error($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'response',
                'store' => $store_name,
                'endpoint' => $endpoint,
                'auth' => 'basic',
                'status' => $code,
                'body' => np_order_hub_wc_api_summarize_body($body),
            ));
        }
        if (!is_wp_error($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
            if ($code >= 200 && $code < 300) {
                return $response;
            }
        }
        np_order_hub_revenue_debug_add($store_key, array(
            'event' => 'fallback',
            'store' => $store_name,
            'endpoint' => $endpoint,
            'auth' => 'query',
            'note' => 'Basic auth failed, retrying with query params.',
        ));
        $params['consumer_key'] = $consumer_key;
        $params['consumer_secret'] = $consumer_secret;
        $args['headers'] = array();
        $url = add_query_arg($params, $url_base);
        np_order_hub_revenue_debug_add($store_key, array(
            'event' => 'request',
            'store' => $store_name,
            'endpoint' => $endpoint,
            'auth' => 'query',
            'url' => $url_base,
            'params' => $debug_params,
        ));
        $response = wp_remote_get($url, $args);
        if (np_order_hub_revenue_debug_enabled() && !is_wp_error($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'response',
                'store' => $store_name,
                'endpoint' => $endpoint,
                'auth' => 'query',
                'status' => $code,
                'body' => np_order_hub_wc_api_summarize_body($body),
            ));
        }
        return $response;
    }

    $params['consumer_key'] = $consumer_key;
    $params['consumer_secret'] = $consumer_secret;
    $url = add_query_arg($params, $url_base);
    np_order_hub_revenue_debug_add($store_key, array(
        'event' => 'request',
        'store' => $store_name,
        'endpoint' => $endpoint,
        'auth' => 'query',
        'url' => $url_base,
        'params' => $debug_params,
    ));
    $response = wp_remote_get($url, $args);
    if (np_order_hub_revenue_debug_enabled() && !is_wp_error($response)) {
        $code = (int) wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        np_order_hub_revenue_debug_add($store_key, array(
            'event' => 'response',
            'store' => $store_name,
            'endpoint' => $endpoint,
            'auth' => 'query',
            'status' => $code,
            'body' => np_order_hub_wc_api_summarize_body($body),
        ));
    }
    return $response;
}

function np_order_hub_wc_api_summarize_body($body) {
    if (!is_string($body) || $body === '') {
        return '';
    }
    $text = wp_strip_all_tags($body);
    $text = preg_replace('/\\s+/', ' ', $text);
    $text = trim($text);
    if ($text === '') {
        return '';
    }
    if (strlen($text) > 200) {
        $text = substr($text, 0, 200) . '...';
    }
    return $text;
}

function np_order_hub_wc_api_error_response($code, $body) {
    $message = 'WooCommerce API returned an error (HTTP ' . (int) $code . ').';
    $summary = np_order_hub_wc_api_summarize_body($body);
    if ($summary !== '') {
        $message .= ' ' . $summary;
    }
    return new WP_Error('api_error', $message, array(
        'status' => (int) $code,
        'body' => $body,
    ));
}

function np_order_hub_wc_api_bad_response($body) {
    $message = 'Unexpected response from WooCommerce API.';
    $summary = np_order_hub_wc_api_summarize_body($body);
    if ($summary !== '') {
        $message .= ' ' . $summary;
    }
    return new WP_Error('bad_response', $message);
}

function np_order_hub_wc_api_invalid_date_param($body, $param) {
    if (!is_string($body) || $body === '') {
        return false;
    }
    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return false;
    }
    if (!empty($decoded['code']) && $decoded['code'] === 'rest_invalid_param') {
        if (!empty($decoded['params'][$param])) {
            return true;
        }
        if (!empty($decoded['data']['params'][$param])) {
            return true;
        }
        if (!empty($decoded['data']['details'][$param])) {
            return true;
        }
    }
    return false;
}

function np_order_hub_revenue_debug_enabled() {
    return !empty($_POST['np_order_hub_import_debug']);
}

function np_order_hub_revenue_debug_add($store_key, $entry) {
    if (!np_order_hub_revenue_debug_enabled()) {
        return;
    }
    global $np_order_hub_revenue_debug;
    if (!is_array($np_order_hub_revenue_debug)) {
        $np_order_hub_revenue_debug = array();
    }
    $store_key = $store_key !== '' ? $store_key : 'unknown';
    if (!isset($np_order_hub_revenue_debug[$store_key])) {
        $np_order_hub_revenue_debug[$store_key] = array();
    }
    if (!isset($entry['time'])) {
        $entry['time'] = current_time('mysql', true);
    }
    $np_order_hub_revenue_debug[$store_key][] = $entry;
}

function np_order_hub_revenue_debug_get() {
    global $np_order_hub_revenue_debug;
    return is_array($np_order_hub_revenue_debug) ? $np_order_hub_revenue_debug : array();
}

function np_order_hub_fetch_store_sales_total_via_orders($store, $date_to_gmt = '') {
    if (!is_array($store) || empty($store['consumer_key']) || empty($store['consumer_secret'])) {
        return new WP_Error('missing_api_credentials', 'Missing WooCommerce API credentials.');
    }

    $excluded_statuses = np_order_hub_get_revenue_excluded_statuses();
    $params = array(
        'per_page' => 100,
        'page' => 1,
        'orderby' => 'date',
        'order' => 'desc',
    );

    $before_candidates = array();
    $before_index = 0;
    if ($date_to_gmt !== '') {
        $timestamp = strtotime($date_to_gmt);
        if ($timestamp) {
            $before_candidates[] = gmdate('Y-m-d\\TH:i:s\\Z', $timestamp);
            $before_candidates[] = gmdate('Y-m-d\\TH:i:s', $timestamp);
            $before_candidates[] = gmdate('Y-m-d', $timestamp);
            $params['before'] = $before_candidates[0];
        }
    }

    $total = 0.0;
    $count = 0;
    $page = 1;
    $max_pages = 200;

    while ($page <= $max_pages) {
        $params['page'] = $page;
        $response = np_order_hub_wc_api_request($store, 'orders', $params, 20);
        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        if ($code < 200 || $code >= 300) {
            $invalid_before = np_order_hub_wc_api_invalid_date_param($body, 'before');
            while ($invalid_before && ($before_index + 1) < count($before_candidates)) {
                $before_index++;
                $params['before'] = $before_candidates[$before_index];
                np_order_hub_revenue_debug_add(isset($store['key']) ? (string) $store['key'] : '', array(
                    'event' => 'retry_before_format',
                    'note' => 'before rejected, retrying with alternate format',
                    'before' => $params['before'],
                ));
                $response = np_order_hub_wc_api_request($store, 'orders', $params, 20);
                if (is_wp_error($response)) {
                    return $response;
                }
                $code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                if ($code >= 200 && $code < 300) {
                    $invalid_before = false;
                    break;
                }
                $invalid_before = np_order_hub_wc_api_invalid_date_param($body, 'before');
            }
            if ($code < 200 || $code >= 300) {
                return np_order_hub_wc_api_error_response($code, $body);
            }
        }

        $orders = $body !== '' ? json_decode($body, true) : null;
        if (!is_array($orders)) {
            return new WP_Error('bad_response', 'Unexpected response from WooCommerce API.');
        }

        if (empty($orders)) {
            break;
        }

        foreach ($orders as $order) {
            if (!is_array($order)) {
                continue;
            }
            $status = isset($order['status']) ? sanitize_key((string) $order['status']) : '';
            if ($status !== '' && in_array($status, $excluded_statuses, true)) {
                continue;
            }
            $total_raw = isset($order['total']) ? (string) $order['total'] : '0';
            if (is_numeric($total_raw)) {
                $total += (float) $total_raw;
            }
            $count++;
        }

        if (count($orders) < $params['per_page']) {
            break;
        }

        $page++;
    }

    return array(
        'total' => (float) $total,
        'count' => (int) $count,
    );
}

function np_order_hub_fetch_store_sales_total($store, $date_to_gmt = '') {
    if (!is_array($store) || empty($store['consumer_key']) || empty($store['consumer_secret'])) {
        return new WP_Error('missing_api_credentials', 'Missing WooCommerce API credentials.');
    }

    $params = array(
        'status' => implode(',', np_order_hub_get_revenue_allowed_statuses()),
    );

    if ($date_to_gmt !== '') {
        $timestamp = strtotime($date_to_gmt);
        if ($timestamp) {
            $params['date_max'] = gmdate('Y-m-d', $timestamp);
        }
    }

    $response = np_order_hub_wc_api_request($store, 'reports/sales', $params, 20);
    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        $fallback = np_order_hub_fetch_store_sales_total_via_orders($store, $date_to_gmt);
        if (!is_wp_error($fallback)) {
            return $fallback;
        }
        return np_order_hub_wc_api_error_response($code, $body);
    }

    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded[0]) || !is_array($decoded[0])) {
        $fallback = np_order_hub_fetch_store_sales_total_via_orders($store, $date_to_gmt);
        if (!is_wp_error($fallback)) {
            return $fallback;
        }
        return np_order_hub_wc_api_bad_response($body);
    }

    $row = $decoded[0];
    $total_raw = isset($row['total_sales']) ? (string) $row['total_sales'] : '0';
    $count_raw = isset($row['total_orders']) ? (int) $row['total_orders'] : 0;
    $total = is_numeric($total_raw) ? (float) $total_raw : 0.0;

    if ($count_raw < 1 && $total <= 0.0) {
        $fallback = np_order_hub_fetch_store_sales_total_via_orders($store, $date_to_gmt);
        if (!is_wp_error($fallback)) {
            return $fallback;
        }
    }

    return array(
        'total' => $total,
        'count' => (int) $count_raw,
    );
}

function np_order_hub_get_revenue_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => '',
        'search' => '',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_period_date_range($period, $custom_from = '', $custom_to = '') {
    $period = sanitize_key((string) $period);
    if (!in_array($period, array('daily', 'month_current', 'month_previous', 'yearly', 'custom'), true)) {
        $period = 'daily';
    }

    $now = current_time('timestamp');
    $today = wp_date('Y-m-d', $now);

    if ($period === 'month_current') {
        $from = wp_date('Y-m-01', $now);
        $to = wp_date('Y-m-t', $now);
    } elseif ($period === 'month_previous') {
        $prev_ts = strtotime('first day of last month', $now);
        $from = wp_date('Y-m-01', $prev_ts);
        $to = wp_date('Y-m-t', $prev_ts);
    } elseif ($period === 'yearly') {
        $year = wp_date('Y', $now);
        $from = $year . '-01-01';
        $to = $year . '-12-31';
    } elseif ($period === 'custom') {
        $from = sanitize_text_field((string) $custom_from);
        $to = sanitize_text_field((string) $custom_to);
        $valid = preg_match('/^\d{4}-\d{2}-\d{2}$/', $from) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $to);
        if (!$valid) {
            $period = 'daily';
            $from = $today;
            $to = $today;
        }
    } else {
        $from = $today;
        $to = $today;
    }

    return array(
        'period' => $period,
        'from' => $from,
        'to' => $to,
    );
}

function np_order_hub_get_norwegian_month_name($timestamp) {
    $month = (int) wp_date('n', $timestamp);
    $names = array(
        1 => 'januar',
        2 => 'februar',
        3 => 'mars',
        4 => 'april',
        5 => 'mai',
        6 => 'juni',
        7 => 'juli',
        8 => 'august',
        9 => 'september',
        10 => 'oktober',
        11 => 'november',
        12 => 'desember',
    );
    return isset($names[$month]) ? $names[$month] : '';
}

function np_order_hub_query_revenue_totals($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $excluded = np_order_hub_get_revenue_excluded_statuses();
    $placeholders = implode(',', array_fill(0, count($excluded), '%s'));
    $exclude_sql = "status NOT IN ($placeholders)";
    $where = $where ? ($where . ' AND ' . $exclude_sql) : ('WHERE ' . $exclude_sql);
    $args = array_merge($args, $excluded);
    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}

function np_order_hub_query_revenue_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $excluded = np_order_hub_get_revenue_excluded_statuses();
    $placeholders = implode(',', array_fill(0, count($excluded), '%s'));
    $exclude_sql = "status NOT IN ($placeholders)";
    $where = $where ? ($where . ' AND ' . $exclude_sql) : ('WHERE ' . $exclude_sql);
    $args = array_merge($args, $excluded);
    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";
    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_item_counts($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $excluded = np_order_hub_get_revenue_excluded_statuses();
    $placeholders = implode(',', array_fill(0, count($excluded), '%s'));
    $exclude_sql = "status NOT IN ($placeholders)";
    $where = $where ? ($where . ' AND ' . $exclude_sql) : ('WHERE ' . $exclude_sql);
    $args = array_merge($args, $excluded);

    $limit = 500;
    $offset = 0;
    $total_items = 0;
    $by_store = array();

    while (true) {
        $sql = "SELECT store_key, payload FROM $table $where ORDER BY id ASC LIMIT %d OFFSET %d";
        $query_args = array_merge($args, array($limit, $offset));
        $rows = $wpdb->get_results($wpdb->prepare($sql, $query_args), ARRAY_A);
        if (empty($rows)) {
            break;
        }
        foreach ($rows as $row) {
            $payload = json_decode((string) ($row['payload'] ?? ''), true);
            $count = np_order_hub_count_line_items($payload);
            if ($count < 1) {
                continue;
            }
            $store_key = isset($row['store_key']) ? sanitize_key((string) $row['store_key']) : '';
            if ($store_key === '') {
                continue;
            }
            if (!isset($by_store[$store_key])) {
                $by_store[$store_key] = 0;
            }
            $by_store[$store_key] += $count;
            $total_items += $count;
        }
        if (count($rows) < $limit) {
            break;
        }
        $offset += $limit;
    }

    return array(
        'total_items' => (int) $total_items,
        'by_store' => $by_store,
    );
}

function np_order_hub_format_money($amount, $currency) {
    $currency = strtoupper(trim((string) $currency));
    $label = '';
    if ($currency === '') {
        $label = 'kr';
    } elseif (in_array($currency, array('NOK', 'SEK', 'DKK'), true)) {
        $label = 'kr';
    } else {
        $label = $currency;
    }
    $formatted = number_format((float) $amount, 0, '', ' ');
    return trim($formatted . ($label !== '' ? ' ' . $label : ''));
}

function np_order_hub_get_pushover_settings() {
    $logo_enabled = (bool) get_option(NP_ORDER_HUB_PUSHOVER_LOGO_ENABLED_OPTION, true);
    $logo_url = trim((string) get_option(NP_ORDER_HUB_PUSHOVER_LOGO_OPTION, ''));
    if ($logo_enabled && $logo_url === '') {
        $logo_url = np_order_hub_get_default_pushover_logo_url();
    }
    return array(
        'enabled' => (bool) get_option(NP_ORDER_HUB_PUSHOVER_ENABLED_OPTION, false),
        'user' => trim((string) get_option(NP_ORDER_HUB_PUSHOVER_USER_OPTION, '')),
        'token' => trim((string) get_option(NP_ORDER_HUB_PUSHOVER_TOKEN_OPTION, '')),
        'title' => trim((string) get_option(NP_ORDER_HUB_PUSHOVER_TITLE_OPTION, 'Order Hub')),
        'logo_enabled' => $logo_enabled,
        'logo_url' => $logo_url,
    );
}

function np_order_hub_get_default_pushover_logo_url() {
    $path = plugin_dir_path(__FILE__) . 'assets/pushover-logo.svg';
    if (!file_exists($path)) {
        return '';
    }
    return plugins_url('assets/pushover-logo.svg', __FILE__);
}

function np_order_hub_pushover_resolve_logo_source($logo_url) {
    $logo_url = trim((string) $logo_url);
    if ($logo_url === '') {
        return array('file' => '', 'cleanup' => false);
    }

    if (preg_match('#^https?://#i', $logo_url)) {
        $plugin_url = plugins_url('/', __FILE__);
        if (strpos($logo_url, $plugin_url) === 0) {
            $relative = ltrim(substr($logo_url, strlen($plugin_url)), '/');
            $file_path = plugin_dir_path(__FILE__) . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            if (is_file($file_path)) {
                return array('file' => $file_path, 'cleanup' => false);
            }
        }
        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $tmp_file = download_url($logo_url);
        if (is_wp_error($tmp_file)) {
            return array('file' => '', 'cleanup' => false);
        }
        return array('file' => $tmp_file, 'cleanup' => true);
    }

    if (is_file($logo_url)) {
        return array('file' => $logo_url, 'cleanup' => false);
    }

    return array('file' => '', 'cleanup' => false);
}

function np_order_hub_pushover_prepare_attachment($logo_url) {
    $source = np_order_hub_pushover_resolve_logo_source($logo_url);
    $file_path = $source['file'];
    if ($file_path === '') {
        return array('attachment' => null, 'tmp_file' => '', 'cleanup' => false);
    }
    if (!function_exists('curl_file_create') && !class_exists('CURLFile')) {
        if (!empty($source['cleanup'])) {
            @unlink($file_path);
        }
        return array('attachment' => null, 'tmp_file' => '', 'cleanup' => false);
    }

    $filename = basename($file_path);
    if ($filename === '') {
        $filename = 'logo.png';
    }
    $mime = 'image/png';
    if (function_exists('mime_content_type')) {
        $detected = mime_content_type($file_path);
        if (is_string($detected) && $detected !== '') {
            $mime = $detected;
        }
    }
    $attachment = function_exists('curl_file_create')
        ? curl_file_create($file_path, $mime, $filename)
        : new CURLFile($file_path, $mime, $filename);

    return array('attachment' => $attachment, 'tmp_file' => $file_path, 'cleanup' => !empty($source['cleanup']));
}

function np_order_hub_send_pushover_message($title, $message) {
    $settings = np_order_hub_get_pushover_settings();
    if (empty($settings['enabled']) || $settings['user'] === '' || $settings['token'] === '') {
        return false;
    }

    $attachment_info = null;
    if (!empty($settings['logo_enabled']) && $settings['logo_url'] !== '') {
        $attachment_info = np_order_hub_pushover_prepare_attachment($settings['logo_url']);
    }
    $attachment_info = is_array($attachment_info) ? $attachment_info : array('attachment' => null, 'tmp_file' => '', 'cleanup' => false);
    $attachment = $attachment_info['attachment'];
    $tmp_file = $attachment_info['tmp_file'];
    $cleanup = !empty($attachment_info['cleanup']);

    $body = array(
        'token' => $settings['token'],
        'user' => $settings['user'],
        'title' => $title,
        'message' => $message,
    );
    if ($attachment) {
        $body['attachment'] = $attachment;
    }

    $response = wp_remote_post('https://api.pushover.net/1/messages.json', array(
        'timeout' => 15,
        'body' => $body,
    ));

    if ($cleanup && $tmp_file !== '' && file_exists($tmp_file)) {
        @unlink($tmp_file);
    }

    return !is_wp_error($response);
}

function np_order_hub_get_help_scout_settings() {
    $status = sanitize_key((string) get_option(NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION, 'pending'));
    if (!in_array($status, array('active', 'pending', 'closed'), true)) {
        $status = 'pending';
    }
    return array(
        'token' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, '')),
        'mailbox_id' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION, 0),
        'default_status' => $status,
        'user_id' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_USER_OPTION, 0),
        'client_id' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION, '')),
        'client_secret' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION, '')),
        'refresh_token' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, '')),
        'expires_at' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0),
    );
}

function np_order_hub_help_scout_get_redirect_url() {
    return admin_url('admin.php?page=np-order-hub-help-scout');
}

function np_order_hub_help_scout_store_tokens($token_data, $fallback_refresh = '') {
    $access_token = isset($token_data['access_token']) ? trim((string) $token_data['access_token']) : '';
    if ($access_token !== '') {
        update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, $access_token);
    }

    $refresh_token = isset($token_data['refresh_token']) ? trim((string) $token_data['refresh_token']) : '';
    if ($refresh_token === '' && $fallback_refresh !== '') {
        $refresh_token = $fallback_refresh;
    }
    if ($refresh_token !== '') {
        update_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, $refresh_token);
    }

    $expires_in = isset($token_data['expires_in']) ? (int) $token_data['expires_in'] : 0;
    if ($expires_in > 0) {
        update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, time() + $expires_in - 60);
    } else {
        update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0);
    }
}

function np_order_hub_help_scout_parse_oauth_error($response, $default_message) {
    $message = $default_message;
    $body = wp_remote_retrieve_body($response);
    $decoded = null;
    if ($body !== '') {
        $decoded = json_decode($body, true);
    }
    if (is_array($decoded)) {
        if (!empty($decoded['error_description'])) {
            $message = (string) $decoded['error_description'];
        } elseif (!empty($decoded['message'])) {
            $message = (string) $decoded['message'];
        } elseif (!empty($decoded['error'])) {
            $message = (string) $decoded['error'];
        }
    } elseif ($body !== '') {
        $message = wp_strip_all_tags((string) $body);
    }
    return $message;
}

function np_order_hub_help_scout_exchange_code($settings, $code) {
    if (empty($settings['client_id']) || empty($settings['client_secret'])) {
        return new WP_Error('missing_help_scout_client', 'Help Scout App ID or Secret missing.');
    }
    $code = trim((string) $code);
    if ($code === '') {
        return new WP_Error('missing_help_scout_code', 'Help Scout OAuth code missing.');
    }

    $response = wp_remote_post('https://api.helpscout.net/v2/oauth2/token', array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret'],
            'redirect_uri' => np_order_hub_help_scout_get_redirect_url(),
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code_status = wp_remote_retrieve_response_code($response);
    if ($code_status < 200 || $code_status >= 300) {
        $message = np_order_hub_help_scout_parse_oauth_error($response, 'Help Scout OAuth exchange failed.');
        return new WP_Error('help_scout_oauth_failed', $message, array(
            'status' => $code_status,
            'body' => wp_remote_retrieve_body($response),
        ));
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['access_token'])) {
        return new WP_Error('help_scout_oauth_failed', 'Help Scout OAuth response missing access token.');
    }

    np_order_hub_help_scout_store_tokens($decoded);

    return $decoded;
}

function np_order_hub_help_scout_refresh_token($settings) {
    if (empty($settings['client_id']) || empty($settings['client_secret'])) {
        return new WP_Error('missing_help_scout_client', 'Help Scout App ID or Secret missing.');
    }
    if (empty($settings['refresh_token'])) {
        return new WP_Error('missing_help_scout_refresh', 'Help Scout refresh token missing.');
    }

    $response = wp_remote_post('https://api.helpscout.net/v2/oauth2/token', array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $settings['refresh_token'],
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret'],
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code_status = wp_remote_retrieve_response_code($response);
    if ($code_status < 200 || $code_status >= 300) {
        $message = np_order_hub_help_scout_parse_oauth_error($response, 'Help Scout OAuth refresh failed.');
        return new WP_Error('help_scout_oauth_failed', $message, array(
            'status' => $code_status,
            'body' => wp_remote_retrieve_body($response),
        ));
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['access_token'])) {
        return new WP_Error('help_scout_oauth_failed', 'Help Scout refresh response missing access token.');
    }

    np_order_hub_help_scout_store_tokens($decoded, $settings['refresh_token']);

    return $decoded;
}

function np_order_hub_help_scout_get_access_token($settings) {
    $token = isset($settings['token']) ? (string) $settings['token'] : '';
    $expires_at = isset($settings['expires_at']) ? (int) $settings['expires_at'] : 0;
    if ($token !== '' && ($expires_at === 0 || time() < $expires_at)) {
        return $token;
    }

    if (!empty($settings['refresh_token'])) {
        $refreshed = np_order_hub_help_scout_refresh_token($settings);
        if (!is_wp_error($refreshed) && !empty($refreshed['access_token'])) {
            return (string) $refreshed['access_token'];
        }
        if (is_wp_error($refreshed)) {
            return $refreshed;
        }
    }

    if ($token !== '') {
        return $token;
    }

    return new WP_Error('missing_help_scout_token', 'Help Scout API token missing.');
}

function np_order_hub_help_scout_clean_payload($value) {
    if (is_array($value)) {
        $clean = array();
        foreach ($value as $key => $item) {
            $clean[$key] = np_order_hub_help_scout_clean_payload($item);
        }
        return $clean;
    }
    if (is_string($value)) {
        return wp_check_invalid_utf8($value);
    }
    return $value;
}

function np_order_hub_help_scout_request($settings, $method, $path, $payload = null) {
    $token = np_order_hub_help_scout_get_access_token($settings);
    if (is_wp_error($token)) {
        return $token;
    }

    $path = ltrim((string) $path, '/');
    if ($path === '') {
        return new WP_Error('missing_help_scout_endpoint', 'Help Scout endpoint missing.');
    }

    $url = 'https://api.helpscout.net/v2/' . $path;
    $args = array(
        'timeout' => 20,
        'headers' => array(
            'Authorization' => 'Bearer ' . $token,
            'Accept' => 'application/json',
        ),
        'method' => strtoupper((string) $method),
    );

    if ($payload !== null) {
        $args['headers']['Content-Type'] = 'application/json';
        $clean_payload = np_order_hub_help_scout_clean_payload($payload);
        $body = wp_json_encode($clean_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            $message = 'Help Scout payload JSON encode failed.';
            if (function_exists('json_last_error_msg')) {
                $message .= ' ' . json_last_error_msg();
            }
            return new WP_Error('help_scout_json_error', $message);
        }
        $args['body'] = $body;
        $args['data_format'] = 'body';
    }

    $response = wp_remote_request($url, $args);
    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    if ($code === 401 && !empty($settings['refresh_token'])) {
        $refreshed = np_order_hub_help_scout_refresh_token($settings);
        if (!is_wp_error($refreshed) && !empty($refreshed['access_token'])) {
            $args['headers']['Authorization'] = 'Bearer ' . (string) $refreshed['access_token'];
            $response = wp_remote_request($url, $args);
            if (is_wp_error($response)) {
                return $response;
            }
            $code = wp_remote_retrieve_response_code($response);
        }
    }
    if ($code < 200 || $code >= 300) {
        $body = wp_remote_retrieve_body($response);
        $request_headers = $args['headers'];
        if (isset($request_headers['Authorization'])) {
            $request_headers['Authorization'] = 'Bearer [redacted]';
        }
        $message = 'Help Scout API returned an error.';
        $decoded = null;
        if ($body !== '') {
            $decoded = json_decode($body, true);
        }
        if (is_array($decoded)) {
            if (!empty($decoded['message'])) {
                $message = (string) $decoded['message'];
            } elseif (!empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            } elseif (!empty($decoded['errors']) && is_array($decoded['errors'])) {
                $parts = array();
                foreach ($decoded['errors'] as $error) {
                    if (is_array($error)) {
                        $field = isset($error['field']) ? (string) $error['field'] : '';
                        $error_message = isset($error['message']) ? (string) $error['message'] : '';
                        $parts[] = $field !== '' ? ($field . ': ' . $error_message) : $error_message;
                    } elseif (is_string($error)) {
                        $parts[] = $error;
                    }
                }
                $parts = array_filter($parts, function ($value) {
                    return $value !== '';
                });
                if (!empty($parts)) {
                    $message = implode(' ', $parts);
                }
            }
        } elseif ($body !== '') {
            $message = wp_strip_all_tags((string) $body);
        }
        $message = 'Help Scout API error (' . $code . '): ' . $message;
        return new WP_Error('help_scout_api_error', $message, array(
            'status' => $code,
            'body' => $body,
            'response_body' => $body,
            'decoded' => $decoded,
            'request_body' => isset($args['body']) ? $args['body'] : '',
            'request_headers' => $request_headers,
            'response_headers' => wp_remote_retrieve_headers($response),
            'request_url' => $url,
        ));
    }

    return $response;
}

function np_order_hub_help_scout_create_conversation($settings, $customer, $subject, $status, $message) {
    if (empty($settings['mailbox_id'])) {
        return new WP_Error('missing_help_scout_mailbox', 'Help Scout mailbox ID missing.');
    }

    $customer = is_array($customer) ? $customer : array();
    if (empty($customer['email'])) {
        return new WP_Error('missing_help_scout_customer', 'Help Scout customer email missing.');
    }

    $payload = array(
        'subject' => $subject,
        'customer' => $customer,
        'mailboxId' => (int) $settings['mailbox_id'],
        'type' => 'email',
        'status' => $status,
        'threads' => array(
            array(
                'type' => 'reply',
                'text' => $message,
                'draft' => false,
                'customer' => array(
                    'email' => (string) $customer['email'],
                ),
            ),
        ),
    );

    $response = np_order_hub_help_scout_request($settings, 'POST', 'conversations', $payload);
    if (is_wp_error($response)) {
        return $response;
    }

    $resource_id = wp_remote_retrieve_header($response, 'resource-id');
    if ($resource_id === '') {
        $resource_id = wp_remote_retrieve_header($response, 'Resource-ID');
    }
    $resource_id = (int) $resource_id;
    if ($resource_id < 1) {
        return new WP_Error('help_scout_missing_id', 'Help Scout conversation ID missing.');
    }

    $web_location = wp_remote_retrieve_header($response, 'web-location');
    if ($web_location === '') {
        $web_location = wp_remote_retrieve_header($response, 'Web-Location');
    }

    return array(
        'id' => $resource_id,
        'web_url' => $web_location !== '' ? (string) $web_location : '',
    );
}

function np_order_hub_help_scout_send_reply($settings, $conversation_id, $message, $status, $customer = array()) {
    $payload = array(
        'text' => $message,
        'type' => 'reply',
        'draft' => false,
    );
    if (is_array($customer) && !empty($customer['id'])) {
        $payload['customer'] = array(
            'id' => (int) $customer['id'],
        );
    } elseif (is_array($customer) && !empty($customer['email'])) {
        $payload['customer'] = array(
            'email' => (string) $customer['email'],
        );
    }
    if (!empty($settings['user_id'])) {
        $payload['user'] = array(
            'id' => (int) $settings['user_id'],
        );
    }

    return np_order_hub_help_scout_request(
        $settings,
        'POST',
        'conversations/' . (int) $conversation_id . '/reply',
        $payload
    );
}

function np_order_hub_help_scout_get_conversation($settings, $conversation_id) {
    $response = np_order_hub_help_scout_request(
        $settings,
        'GET',
        'conversations/' . (int) $conversation_id
    );
    if (is_wp_error($response)) {
        return $response;
    }
    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded)) {
        return new WP_Error('help_scout_bad_response', 'Help Scout conversation response missing JSON.');
    }
    return $decoded;
}

function np_order_hub_help_scout_extract_customer_id($conversation) {
    if (!is_array($conversation)) {
        return 0;
    }
    $candidates = array(
        isset($conversation['primaryCustomer']['id']) ? (int) $conversation['primaryCustomer']['id'] : 0,
        isset($conversation['customer']['id']) ? (int) $conversation['customer']['id'] : 0,
    );
    foreach ($candidates as $candidate) {
        if ($candidate > 0) {
            return $candidate;
        }
    }
    if (!empty($conversation['_embedded']) && is_array($conversation['_embedded'])) {
        foreach (array('primaryCustomer', 'customer') as $key) {
            if (!empty($conversation['_embedded'][$key]['id'])) {
                return (int) $conversation['_embedded'][$key]['id'];
            }
        }
    }
    return 0;
}

function np_order_hub_maybe_notify_new_order($store, $order_number, $order_id, $status, $total, $currency) {
    $settings = np_order_hub_get_pushover_settings();
    if (empty($settings['enabled']) || $settings['user'] === '' || $settings['token'] === '') {
        return;
    }
    $store_name = is_array($store) && !empty($store['name']) ? (string) $store['name'] : 'Store';
    $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
    $total_display = np_order_hub_format_money((float) $total, (string) $currency);
    $status_label = $status !== '' ? ucwords(str_replace('-', ' ', (string) $status)) : '';
    $message = 'Ny ordre ' . $store_name . ' ' . $label . ' - ' . $total_display;
    if ($status_label !== '') {
        $message .= ' (' . $status_label . ')';
    }
    $title = $settings['title'] !== '' ? $settings['title'] : 'Order Hub';
    np_order_hub_send_pushover_message($title, $message);
}

function np_order_hub_get_allowed_statuses() {
    return array(
        'pending' => 'Pending',
        'processing' => 'Processing',
        'restordre' => 'Restordre',
        'completed' => 'Completed',
        'on-hold' => 'On-hold',
        'cancelled' => 'Cancelled',
        'refunded' => 'Refunded',
        'reklamasjon' => 'Reklamasjon',
        'failed' => 'Failed',
    );
}

function np_order_hub_update_remote_order_status($store, $order_id, $status) {
    $order_id = (int) $order_id;
    $status = sanitize_key((string) $status);
    if ($order_id < 1 || $status === '') {
        return new WP_Error('missing_params', 'Missing order ID or status.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_token', 'Store token missing.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'order-status');
    if ($endpoint === '') {
        return new WP_Error('missing_endpoint', 'Store endpoint missing.');
    }

    $response = wp_remote_post($endpoint, array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'order_id' => $order_id,
            'status' => $status,
            'token' => $token,
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        $message = 'Status update failed.';
        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (is_array($decoded) && !empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            }
        }
        return new WP_Error('status_update_failed', $message, array(
            'status' => $code,
            'body' => $body,
        ));
    }

    return true;
}

function np_order_hub_create_remote_reklamasjon_order($store, $order_id, $items, $allow_oos = false) {
    $order_id = (int) $order_id;
    if ($order_id < 1 || empty($items) || !is_array($items)) {
        return new WP_Error('missing_params', 'Missing order ID or items.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_token', 'Store token missing.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'reklamasjon-order');
    if ($endpoint === '') {
        return new WP_Error('missing_endpoint', 'Store endpoint missing.');
    }

    $response = wp_remote_post($endpoint, array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ),
        'body' => wp_json_encode(array(
            'order_id' => $order_id,
            'items' => array_values($items),
            'allow_oos' => $allow_oos ? true : false,
            'token' => $token,
        )),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        $message = 'Claim order creation failed.';
        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (is_array($decoded) && !empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            }
        }
        $error_code = $code === 409 ? 'stock_unavailable' : 'claim_order_failed';
        return new WP_Error($error_code, $message, array(
            'status' => $code,
            'body' => $body,
        ));
    }

    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (is_array($decoded)) {
        return $decoded;
    }
    return array('status' => 'ok');
}

function np_order_hub_apply_local_status($record, $status) {
    if (!is_array($record) || empty($record['id'])) {
        return $record;
    }
    global $wpdb;
    $table = np_order_hub_table_name();

    $update = array(
        'status' => $status,
        'updated_at_gmt' => current_time('mysql', true),
    );
    if (!empty($record['payload'])) {
        $decoded = json_decode($record['payload'], true);
        if (is_array($decoded)) {
            $decoded['status'] = $status;
            $update['payload'] = wp_json_encode($decoded);
        }
    }
    $wpdb->update($table, $update, array('id' => (int) $record['id']));

    $record['status'] = $status;
    if (!empty($update['payload'])) {
        $record['payload'] = $update['payload'];
    }
    return $record;
}

function np_order_hub_dashboard_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $page_slug = isset($_GET['page']) ? sanitize_key((string) $_GET['page']) : 'np-order-hub-dashboard';
    $delivery_bucket = $page_slug === 'np-order-hub-scheduled' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
    $dashboard_title = $delivery_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
    $default_status = $delivery_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? '' : 'processing';
    $show_status_filter = true;
    $show_status_tabs = true;
    $show_reklamasjon = $delivery_bucket !== NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED;

    $bulk_notice = null;
    if (!empty($_POST['np_order_hub_bulk_action'])) {
        check_admin_referer('np_order_hub_bulk_action');
        $action = sanitize_key((string) $_POST['np_order_hub_bulk_action']);
        $bulk_status = sanitize_key((string) ($_POST['bulk_status'] ?? ''));
        $record_ids = isset($_POST['order_ids']) ? array_map('absint', (array) $_POST['order_ids']) : array();
        $record_ids = array_filter($record_ids, function ($value) {
            return $value > 0;
        });

        $allowed_actions = array('packing_slips', 'update_status', 'delete_from_hub', 'mark_scheduled', 'mark_standard');
        if (!in_array($action, $allowed_actions, true)) {
            $bulk_notice = array('type' => 'error', 'message' => 'Unknown bulk action.');
        } elseif (empty($record_ids)) {
            $bulk_notice = array('type' => 'error', 'message' => 'Select at least one order.');
        } else {
            global $wpdb;
            $table = np_order_hub_table_name();
            $placeholders = implode(',', array_fill(0, count($record_ids), '%d'));
            $records = $wpdb->get_results(
                $wpdb->prepare("SELECT * FROM $table WHERE id IN ($placeholders)", $record_ids),
                ARRAY_A
            );

            if (empty($records)) {
                $bulk_notice = array('type' => 'error', 'message' => 'Orders not found.');
            } elseif ($action === 'delete_from_hub') {
                $deleted = $wpdb->query(
                    $wpdb->prepare("DELETE FROM $table WHERE id IN ($placeholders)", $record_ids)
                );
                if ($deleted === false) {
                    $bulk_notice = array('type' => 'error', 'message' => 'Failed to delete orders.');
                } elseif ($deleted < 1) {
                    $bulk_notice = array('type' => 'error', 'message' => 'No orders were deleted.');
                } else {
                    $bulk_notice = array('type' => 'success', 'message' => 'Deleted ' . $deleted . ' orders from hub.');
                }
            } elseif (in_array($action, array('mark_scheduled', 'mark_standard'), true)) {
                $target_bucket = $action === 'mark_scheduled' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
                $updated = 0;
                foreach ($records as $record) {
                    np_order_hub_update_delivery_bucket($record, $target_bucket);
                    $updated++;
                }
                if ($updated < 1) {
                    $bulk_notice = array('type' => 'error', 'message' => 'No orders were updated.');
                } else {
                    $label = $target_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
                    $bulk_notice = array('type' => 'success', 'message' => 'Moved ' . $updated . ' orders to ' . $label . '.');
                }
            } else {
                $store_keys = array_values(array_unique(array_filter(array_map(function ($row) {
                    return isset($row['store_key']) ? (string) $row['store_key'] : '';
                }, $records))));

                if ($action === 'packing_slips') {
                    if (count($store_keys) === 1) {
                        $store = np_order_hub_get_store_by_key($store_keys[0]);
                        $order_ids = array_map(function ($row) {
                            return isset($row['order_id']) ? (int) $row['order_id'] : 0;
                        }, $records);
                        $order_ids = array_filter($order_ids, function ($value) {
                            return $value > 0;
                        });
                        $bulk_url = np_order_hub_build_packing_slips_url($store, $order_ids);
                        if ($bulk_url === '') {
                            $bulk_notice = array('type' => 'error', 'message' => 'Packing slip bulk URL is not configured for this store.');
                        } else {
                            wp_redirect($bulk_url);
                            exit;
                        }
                    } else {
                        $groups = array();
                        $missing_stores = array();
                        foreach ($records as $record) {
                            $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
                            $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
                            if ($store_key === '' || $order_id < 1) {
                                continue;
                            }
                            if (!isset($groups[$store_key])) {
                                $store = np_order_hub_get_store_by_key($store_key);
                                if (!$store) {
                                    $missing_stores[$store_key] = true;
                                    continue;
                                }
                                $groups[$store_key] = array(
                                    'store' => $store,
                                    'order_ids' => array(),
                                );
                            }
                            if (isset($groups[$store_key])) {
                                $groups[$store_key]['order_ids'][] = $order_id;
                            }
                        }

                        if (!empty($missing_stores)) {
                            $bulk_notice = array(
                                'type' => 'error',
                                'message' => 'Stores not found: ' . implode(', ', array_keys($missing_stores)) . '.',
                            );
                        } elseif (empty($groups)) {
                            $bulk_notice = array('type' => 'error', 'message' => 'Orders not found.');
                        } else {
                            $bundle = np_order_hub_build_packing_slips_bundle($groups);
                            if (is_wp_error($bundle)) {
                                $bulk_notice = array('type' => 'error', 'message' => $bundle->get_error_message());
                            } elseif (!empty($bundle['preview_links'])) {
                                $merge_error = isset($bundle['merge_error']) ? (string) $bundle['merge_error'] : '';
                                np_order_hub_send_packing_slips_preview_page($bundle['preview_links'], $merge_error);
                                exit;
                            } else {
                                np_order_hub_send_download($bundle);
                                exit;
                            }
                        }
                    }
                } else {
                    $allowed_statuses = np_order_hub_get_allowed_statuses();
                    if (empty($bulk_status) || !isset($allowed_statuses[$bulk_status])) {
                        $bulk_notice = array('type' => 'error', 'message' => 'Select a valid status for bulk update.');
                    } else {
                        $updated = 0;
                        $failed = 0;
                        $first_error = '';
                        $missing_stores = array();
                        $missing_tokens = array();
                        $store_cache = array();

                        foreach ($records as $record) {
                            $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
                            $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
                            if ($order_id < 1 || $store_key === '') {
                                $failed++;
                                continue;
                            }

                            if (!array_key_exists($store_key, $store_cache)) {
                                $store_cache[$store_key] = np_order_hub_get_store_by_key($store_key);
                            }
                            $store = $store_cache[$store_key];
                            if (!$store) {
                                $missing_stores[$store_key] = true;
                                $failed++;
                                continue;
                            }

                            $token = np_order_hub_get_store_token($store);
                            if ($token === '') {
                                $missing_tokens[$store_key] = true;
                                $failed++;
                                continue;
                            }

                            $result = np_order_hub_update_remote_order_status($store, $order_id, $bulk_status);
                            if (is_wp_error($result)) {
                                $failed++;
                                if ($first_error === '') {
                                    $first_error = $result->get_error_message();
                                }
                                continue;
                            }
                            np_order_hub_apply_local_status($record, $bulk_status);
                            $updated++;
                        }

                        if ($updated > 0 && $failed === 0) {
                            $bulk_notice = array('type' => 'success', 'message' => 'Updated ' . $updated . ' orders.');
                        } else {
                            $message = $updated > 0
                                ? 'Updated ' . $updated . ' orders, ' . $failed . ' failed.'
                                : 'No orders were updated.';
                            if (!empty($missing_stores)) {
                                $message .= ' Missing stores: ' . implode(', ', array_keys($missing_stores)) . '.';
                            }
                            if (!empty($missing_tokens)) {
                                $message .= ' Missing store tokens: ' . implode(', ', array_keys($missing_tokens)) . '.';
                            }
                            if ($first_error !== '') {
                                $message .= ' First error: ' . $first_error;
                            }
                            $bulk_notice = array('type' => 'error', 'message' => $message);
                        }
                    }
                }
            }
        }
    }

    $filters = np_order_hub_get_dashboard_filters($default_status);
    $metric_filters = array(
        'store' => $filters['store'],
        'status' => $filters['status'],
    );

    $currency_label = np_order_hub_get_currency_label($metric_filters, $delivery_bucket);
    $now_gmt = current_time('timestamp', true);
    $today_local = current_time('Y-m-d');
    $today_start = get_gmt_from_date($today_local . ' 00:00:00');
    $today_end = get_gmt_from_date($today_local . ' 23:59:59');

    $metrics = array(
        array(
            'label' => 'Today',
            'data' => np_order_hub_query_metric_range($metric_filters, $today_start, $today_end, $delivery_bucket),
        ),
        array(
            'label' => 'Last 7 days',
            'data' => np_order_hub_query_metric_range($metric_filters, gmdate('Y-m-d H:i:s', $now_gmt - (7 * DAY_IN_SECONDS)), gmdate('Y-m-d H:i:s', $now_gmt), $delivery_bucket),
        ),
        array(
            'label' => 'Last 30 days',
            'data' => np_order_hub_query_metric_range($metric_filters, gmdate('Y-m-d H:i:s', $now_gmt - (30 * DAY_IN_SECONDS)), gmdate('Y-m-d H:i:s', $now_gmt), $delivery_bucket),
        ),
        array(
            'label' => 'All time',
            'data' => np_order_hub_query_metric_range($metric_filters, '', '', $delivery_bucket),
        ),
    );

    $reklamasjon_rows = array();
    $reklamasjon_totals = array('count' => 0, 'total' => 0.0);
    $reklamasjon_currency = '';
    if ($show_reklamasjon) {
        $reklamasjon_filters = array(
            'date_from' => $filters['date_from'],
            'date_to' => $filters['date_to'],
        );
        $reklamasjon_rows = np_order_hub_query_reklamasjon_by_store($reklamasjon_filters);
        $reklamasjon_totals = np_order_hub_query_reklamasjon_totals(
            array(),
            $filters['date_from'],
            $filters['date_to']
        );
        if (!empty($reklamasjon_rows)) {
            $reklamasjon_currencies = array_values(array_unique(array_filter(array_map(function ($row) {
                return isset($row['currency']) ? (string) $row['currency'] : '';
            }, $reklamasjon_rows))));
            if (count($reklamasjon_currencies) === 1) {
                $reklamasjon_currency = (string) $reklamasjon_currencies[0];
            }
        }
    }

    $per_page = NP_ORDER_HUB_PER_PAGE;
    $current_page = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1;
    $offset = ($current_page - 1) * $per_page;
    $total_items = 0;
    $orders = np_order_hub_query_orders($filters, $per_page, $offset, $total_items, $delivery_bucket);
    $total_pages = $per_page > 0 ? (int) ceil($total_items / $per_page) : 1;

    $stores = np_order_hub_get_stores();
    $store_options = array();
    $store_currency_map = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
            if (!empty($store['currency'])) {
                $store_currency_map[$store['key']] = (string) $store['currency'];
            }
        }
    }
    $statuses = array();
    if ($show_status_filter) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $status_args = array();
        $status_filters = array('store' => $filters['store']);
        $status_where = np_order_hub_build_where_clause($status_filters, $status_args, false, false);
        $status_sql = "SELECT DISTINCT status FROM $table $status_where ORDER BY status";
        $status_rows = $status_args ? $wpdb->get_col($wpdb->prepare($status_sql, $status_args)) : $wpdb->get_col($status_sql);
        foreach ((array) $status_rows as $status) {
            $status = sanitize_key((string) $status);
            if ($status !== '') {
                $statuses[$status] = ucwords(str_replace('-', ' ', $status));
            }
        }
    }

    $base_url = admin_url('admin.php?page=' . ($delivery_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'np-order-hub-scheduled' : 'np-order-hub-dashboard'));
    $clear_url = $base_url;
    $filter_query = array();
    $filter_keys = array('store', 'date_from', 'date_to', 's');
    if ($show_status_filter) {
        $filter_keys[] = 'status';
    }
    foreach ($filter_keys as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    $status_tabs = array(
        '' => 'All',
        'processing' => 'Processing',
        'restordre' => 'Restordre',
        'on-hold' => 'On hold',
        'completed' => 'Completed',
    );

    echo '<div class="wrap np-order-hub-dashboard">';
    if (!empty($bulk_notice) && is_array($bulk_notice)) {
        $type = $bulk_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($bulk_notice['message']) ? (string) $bulk_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }
    echo '<h1>' . esc_html($dashboard_title) . '</h1>';
    echo '<style>
        .np-order-hub-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:16px 0 24px;}
        .np-order-hub-card{padding:16px;}
        .np-order-hub-card h3{margin:0 0 8px;font-size:14px;font-weight:600;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-status{display:inline-block;padding:2px 8px;border-radius:12px;background:#f0f0f1;font-size:12px;}
        .np-order-hub-actions .button{margin-right:6px;}
        .np-order-hub-pagination{margin-top:16px;}
        .np-order-hub-pagination .tablenav{padding:0;}
        .np-order-hub-reklamasjon{margin:24px 0;}
        .np-order-hub-reklamasjon .card{max-width:320px;}
        .np-order-hub-reklamasjon table{margin-top:12px;}
        .np-order-hub-status-tabs{margin:16px 0 8px;}
    </style>';

    echo '<div class="np-order-hub-cards">';
    foreach ($metrics as $metric) {
        $count = isset($metric['data']['count']) ? (int) $metric['data']['count'] : 0;
        $total = isset($metric['data']['total']) ? (float) $metric['data']['total'] : 0.0;
        $total_display = np_order_hub_format_money($total, $currency_label);
        echo '<div class="card np-order-hub-card">';
        echo '<h3>' . esc_html($metric['label']) . '</h3>';
        echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
        echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
        echo '</div>';
    }
    echo '</div>';

    if ($show_reklamasjon) {
        echo '<div class="np-order-hub-reklamasjon">';
        echo '<h2>Reklamasjon oversikt</h2>';
        if ($filters['date_from'] !== '' || $filters['date_to'] !== '') {
            echo '<p class="description">Bruker valgt datoperiode.</p>';
        }
        $reklamasjon_total_display = np_order_hub_format_money(
            isset($reklamasjon_totals['total']) ? (float) $reklamasjon_totals['total'] : 0.0,
            $reklamasjon_currency
        );
        $reklamasjon_count = isset($reklamasjon_totals['count']) ? (int) $reklamasjon_totals['count'] : 0;
        echo '<div class="card np-order-hub-card">';
        echo '<h3>Reklamasjon totalt</h3>';
        echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $reklamasjon_count) . '</strong></div>';
        echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($reklamasjon_total_display) . '</strong></div>';
        echo '</div>';

        echo '</div>';
    }

    if ($show_status_tabs) {
        echo '<h2 class="nav-tab-wrapper np-order-hub-status-tabs">';
        foreach ($status_tabs as $status_key => $status_label) {
            $tab_query = $filter_query;
            if ($status_key === '') {
                $tab_query['status'] = 'all';
            } else {
                $tab_query['status'] = $status_key;
            }
            $tab_url = add_query_arg($tab_query, $base_url);
            $active = $filters['status'] === $status_key ? ' nav-tab-active' : '';
            echo '<a class="nav-tab' . esc_attr($active) . '" href="' . esc_url($tab_url) . '">' . esc_html($status_label) . '</a>';
        }
        echo '</h2>';
    }

    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="' . esc_attr($page_slug) . '" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-store">Store</label>';
    echo '<select id="np-order-hub-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    if ($show_status_filter) {
        echo '<div class="field">';
        echo '<label for="np-order-hub-status">Status</label>';
        echo '<select id="np-order-hub-status" name="status">';
        echo '<option value="">All statuses</option>';
        foreach ($statuses as $key => $label) {
            $selected = $filters['status'] === $key ? ' selected' : '';
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        echo '</div>';
    }

    echo '<div class="field">';
    echo '<label for="np-order-hub-date-from">From</label>';
    echo '<input id="np-order-hub-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-date-to">To</label>';
    echo '<input id="np-order-hub-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-search">Search</label>';
    echo '<input id="np-order-hub-search" type="search" name="s" value="' . esc_attr($filters['search']) . '" placeholder="Order number or ID" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($clear_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $bulk_action_url = add_query_arg($filter_query, $base_url);
    echo '<form method="post" class="np-order-hub-bulk" action="' . esc_url($bulk_action_url) . '">';
    wp_nonce_field('np_order_hub_bulk_action');
    echo '<div class="tablenav top">';
    echo '<div class="alignleft actions">';
    echo '<label class="screen-reader-text" for="np-order-hub-bulk-action">Bulk actions</label>';
    echo '<select id="np-order-hub-bulk-action" name="np_order_hub_bulk_action">';
    echo '<option value="">Bulk actions</option>';
    echo '<option value="packing_slips">Download packing slips</option>';
    echo '<option value="update_status">Update status</option>';
    echo '<option value="mark_scheduled">Move to Levering til bestemt dato</option>';
    echo '<option value="mark_standard">Move to Levering 3-5 dager</option>';
    echo '<option value="delete_from_hub">Delete from hub</option>';
    echo '</select>';
    echo '<label class="screen-reader-text" for="np-order-hub-bulk-status">Bulk status</label>';
    echo '<select id="np-order-hub-bulk-status" name="bulk_status">';
    echo '<option value="">Select status</option>';
    foreach (np_order_hub_get_allowed_statuses() as $key => $label) {
        echo '<option value="' . esc_attr($key) . '">' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '<button class="button" type="submit">Apply</button>';
    echo '</div>';
    echo '</div>';

    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th class="check-column"><input type="checkbox" id="np-order-hub-select-all" /></th>';
    echo '<th>Order</th>';
    echo '<th>Customer</th>';
    echo '<th>Store</th>';
    echo '<th>Date</th>';
    echo '<th>Status</th>';
    echo '<th>Reklamasjon</th>';
    echo '<th>Total</th>';
    echo '<th>Actions</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($orders)) {
        echo '<tr><td colspan="9">No orders found.</td></tr>';
    } else {
        foreach ($orders as $order) {
            $order_id = isset($order['order_id']) ? (int) $order['order_id'] : 0;
            $order_number = isset($order['order_number']) ? (string) $order['order_number'] : '';
            $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
            $customer_label = np_order_hub_get_customer_label($order);
            $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
            $date_label = '';
            if (!empty($order['date_created_gmt']) && $order['date_created_gmt'] !== '0000-00-00 00:00:00') {
                $date_label = get_date_from_gmt($order['date_created_gmt'], 'd.m.y');
            }
            $status_label = '';
            if (!empty($order['status'])) {
                $status_label = ucwords(str_replace('-', ' ', (string) $order['status']));
            }
            $total_display = np_order_hub_format_money(isset($order['total']) ? (float) $order['total'] : 0.0, isset($order['currency']) ? (string) $order['currency'] : '');
            $is_reklamasjon = np_order_hub_record_is_reklamasjon($order);
            $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $order['id']);
            $open_url = isset($order['order_admin_url']) ? (string) $order['order_admin_url'] : '';
            $store = np_order_hub_get_store_by_key(isset($order['store_key']) ? $order['store_key'] : '');
            $packing_url = np_order_hub_build_packing_slip_url(
                $store,
                $order_id,
                $order_number,
                isset($order['payload']) ? $order['payload'] : null
            );

            echo '<tr>';
            echo '<td class="check-column"><input type="checkbox" name="order_ids[]" value="' . esc_attr((string) $order['id']) . '" /></td>';
            echo '<td>' . esc_html($label) . '</td>';
            echo '<td>' . esc_html($customer_label) . '</td>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html($date_label) . '</td>';
            echo '<td>';
            if ($status_label !== '') {
                echo '<span class="np-order-hub-status">' . esc_html($status_label) . '</span>';
            }
            echo '</td>';
            echo '<td>' . ($is_reklamasjon ? '<span class="np-order-hub-status">Ja</span>' : '—') . '</td>';
            echo '<td>' . esc_html($total_display) . '</td>';
            echo '<td class="np-order-hub-actions">';
            echo '<a class="button button-small" href="' . esc_url($details_url) . '">Details</a>';
            if ($packing_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
            }
            if ($open_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($open_url) . '" target="_blank" rel="noopener">Open order</a>';
            }
            echo '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';
    echo '</form>';

    if ($total_pages > 1) {
        $pagination_base = add_query_arg($filter_query, $base_url);
        $pagination_links = paginate_links(array(
            'base' => add_query_arg('paged', '%#%', $pagination_base),
            'format' => '',
            'current' => $current_page,
            'total' => $total_pages,
            'prev_text' => '&laquo;',
            'next_text' => '&raquo;',
        ));
        if ($pagination_links) {
            echo '<div class="np-order-hub-pagination">';
            echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post($pagination_links) . '</div></div>';
            echo '</div>';
        }
    }

    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var selectAll = document.getElementById("np-order-hub-select-all");
            if (selectAll) {
                selectAll.addEventListener("change", function() {
                    var boxes = document.querySelectorAll(".np-order-hub-bulk input[name=\'order_ids[]\']");
                    boxes.forEach(function(box) {
                        box.checked = selectAll.checked;
                    });
                });
            }

            var bulkAction = document.getElementById("np-order-hub-bulk-action");
            var bulkStatus = document.getElementById("np-order-hub-bulk-status");
            var toggleBulkStatus = function() {
                if (!bulkStatus || !bulkAction) {
                    return;
                }
                bulkStatus.disabled = bulkAction.value !== "update_status";
            };
            if (bulkAction && bulkStatus) {
                toggleBulkStatus();
                bulkAction.addEventListener("change", toggleBulkStatus);
            }

            var bulkForm = document.querySelector(".np-order-hub-bulk");
            if (bulkForm && bulkAction) {
                bulkForm.addEventListener("submit", function(event) {
                    if (bulkAction.value === "delete_from_hub") {
                        if (!window.confirm("Delete selected orders from hub?")) {
                            event.preventDefault();
                        }
                    }
                });
            }
        });
    </script>';

    echo '</div>';
}

function np_order_hub_revenue_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $history_seed = np_order_hub_get_historical_revenue();
    $manual_revenue = np_order_hub_get_manual_revenue();
    $existing_history_keys = array();
    foreach ($history_seed as $key => $value) {
        $key = sanitize_key((string) $key);
        if ($key !== '') {
            $existing_history_keys[$key] = true;
        }
    }
    foreach ($manual_revenue as $key => $value) {
        $key = sanitize_key((string) $key);
        if ($key !== '') {
            $existing_history_keys[$key] = true;
        }
    }
    $importable_store_options = $store_options;
    foreach ($existing_history_keys as $key => $unused) {
        if (isset($importable_store_options[$key])) {
            unset($importable_store_options[$key]);
        }
    }

    $selected_import_stores = array();
    $has_import_selection = isset($_POST['np_order_hub_import_stores']);
    if ($has_import_selection) {
        $selected_import_stores = array_values(array_filter(array_map(function ($value) {
            return sanitize_key((string) $value);
        }, (array) $_POST['np_order_hub_import_stores'])));
        if (!empty($importable_store_options)) {
            $selected_import_stores = array_values(array_intersect($selected_import_stores, array_keys($importable_store_options)));
        }
    } else {
        $selected_import_stores = array_keys($importable_store_options);
    }

    $import_notice = '';
    $import_errors = array();
    if (!empty($_POST['np_order_hub_import_revenue']) && check_admin_referer('np_order_hub_import_revenue')) {
        $history = np_order_hub_get_historical_revenue();
        $skip_history_keys = array();
        foreach ($history as $key => $value) {
            $key = sanitize_key((string) $key);
            if ($key !== '') {
                $skip_history_keys[$key] = true;
            }
        }
        foreach ($manual_revenue as $key => $value) {
            $key = sanitize_key((string) $key);
            if ($key !== '') {
                $skip_history_keys[$key] = true;
            }
        }
        $imported = 0;
        if ($has_import_selection && empty($selected_import_stores)) {
            $import_errors[] = 'Select at least one store to import.';
        }
        foreach ($stores as $store) {
            if (!is_array($store) || empty($store['key'])) {
                continue;
            }
            $store_key = sanitize_key((string) $store['key']);
            if ($has_import_selection && !in_array($store_key, $selected_import_stores, true)) {
                continue;
            }
            if (isset($skip_history_keys[$store_key])) {
                continue;
            }
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_start',
                'store' => isset($store['name']) ? (string) $store['name'] : $store_key,
                'has_api' => !empty($store['consumer_key']) && !empty($store['consumer_secret']),
            ));
            if (empty($store['consumer_key']) || empty($store['consumer_secret'])) {
                $import_errors[] = 'Missing API keys for ' . (isset($store['name']) ? (string) $store['name'] : $store['key']);
                np_order_hub_revenue_debug_add($store_key, array(
                    'event' => 'import_error',
                    'message' => 'Missing API keys.',
                ));
                continue;
            }
            $date_to_gmt = np_order_hub_get_store_first_order_gmt($store_key);
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_date',
                'date_to_gmt' => $date_to_gmt,
            ));
            $result = np_order_hub_fetch_store_sales_total($store, $date_to_gmt);
            if (is_wp_error($result)) {
                $import_errors[] = 'API error for ' . (isset($store['name']) ? (string) $store['name'] : $store['key']) . ': ' . $result->get_error_message();
                np_order_hub_revenue_debug_add($store_key, array(
                    'event' => 'import_error',
                    'message' => $result->get_error_message(),
                ));
                continue;
            }
            $history[$store_key] = array(
                'total' => isset($result['total']) ? (float) $result['total'] : 0.0,
                'count' => isset($result['count']) ? (int) $result['count'] : 0,
                'currency' => isset($store['currency']) ? (string) $store['currency'] : '',
                'date_to_gmt' => $date_to_gmt,
                'updated_at_gmt' => current_time('mysql', true),
            );
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_ok',
                'total' => isset($result['total']) ? (float) $result['total'] : 0.0,
                'count' => isset($result['count']) ? (int) $result['count'] : 0,
            ));
            $imported++;
        }
        np_order_hub_save_historical_revenue($history);
        if ($imported > 0) {
            $import_notice = 'Historical revenue imported.';
        }
        if ($imported === 0 && empty($import_errors)) {
            if (empty($importable_store_options)) {
                $import_errors[] = 'Alle butikker har allerede historisk omsetning.';
            } else {
                $import_errors[] = 'No stores were imported. Add API credentials first.';
            }
        }
    }

    $filters = np_order_hub_get_revenue_filters();

    $rows = np_order_hub_query_revenue_by_store($filters);
    $totals = np_order_hub_query_revenue_totals($filters);
    $item_counts = np_order_hub_query_item_counts($filters);
    $items_by_store = isset($item_counts['by_store']) && is_array($item_counts['by_store']) ? $item_counts['by_store'] : array();
    $history = np_order_hub_get_historical_revenue();
    if (!empty($manual_revenue)) {
        foreach ($manual_revenue as $store_key => $manual) {
            if (!is_array($manual)) {
                continue;
            }
            $store_key = sanitize_key((string) $store_key);
            if ($store_key === '') {
                continue;
            }
            $history[$store_key] = array(
                'total' => isset($manual['total']) ? (float) $manual['total'] : 0.0,
                'count' => isset($manual['count']) ? (int) $manual['count'] : 0,
                'currency' => isset($manual['currency']) ? (string) $manual['currency'] : '',
                'date_to_gmt' => isset($manual['date_to_gmt']) ? (string) $manual['date_to_gmt'] : '',
                'updated_at_gmt' => isset($manual['updated_at_gmt']) ? (string) $manual['updated_at_gmt'] : current_time('mysql', true),
                'manual' => true,
            );
        }
    }
    $include_history = ($filters['date_from_raw'] === '' && $filters['date_to_raw'] === '');
    $history_total = 0.0;
    $history_count = 0;
    if ($include_history && !empty($history)) {
        $rows_by_key = array();
        foreach ($rows as $row) {
            if (!empty($row['store_key'])) {
                $rows_by_key[(string) $row['store_key']] = $row;
            }
        }
        foreach ($history as $store_key => $hist) {
            $store_key = sanitize_key((string) $store_key);
            if ($store_key === '') {
                continue;
            }
            if (!isset($rows_by_key[$store_key])) {
                $rows_by_key[$store_key] = array(
                    'store_key' => $store_key,
                    'store_name' => isset($store_options[$store_key]) ? $store_options[$store_key] : $store_key,
                    'currency' => isset($hist['currency']) ? (string) $hist['currency'] : '',
                    'count' => 0,
                    'total' => 0.0,
                );
            }
            $hist_total = isset($hist['total']) ? (float) $hist['total'] : 0.0;
            $hist_count = isset($hist['count']) ? (int) $hist['count'] : 0;
            $rows_by_key[$store_key]['total'] = (float) $rows_by_key[$store_key]['total'] + $hist_total;
            $rows_by_key[$store_key]['count'] = (int) $rows_by_key[$store_key]['count'] + $hist_count;
            $history_total += $hist_total;
            $history_count += $hist_count;
        }
        $rows = array_values($rows_by_key);
        $totals['total'] = (float) $totals['total'] + $history_total;
        $totals['count'] = (int) $totals['count'] + $history_count;
    }
    if (!empty($rows)) {
        usort($rows, function ($a, $b) {
            $store_cmp = strcmp((string) ($a['store_name'] ?? ''), (string) ($b['store_name'] ?? ''));
            if ($store_cmp !== 0) {
                return $store_cmp;
            }
            return strcmp((string) ($a['store_key'] ?? ''), (string) ($b['store_key'] ?? ''));
        });
    }

    $currency_label = '';
    $has_multiple_currencies = false;
    if (!empty($rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $rows))));
        $currency_count = count($currencies);
        if ($currency_count === 1) {
            $currency_label = (string) $currencies[0];
        }
        $has_multiple_currencies = $currency_count > 1;
    }

    $total_display = np_order_hub_format_money((float) $totals['total'], $currency_label);
    $count = isset($totals['count']) ? (int) $totals['count'] : 0;

    $base_url = admin_url('admin.php?page=np-order-hub-revenue');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-revenue-page">';
    echo '<h1>Omsetning</h1>';
    if ($import_notice !== '') {
        echo '<div class="updated"><p>' . esc_html($import_notice) . '</p></div>';
    }
    if (!empty($import_errors)) {
        foreach ($import_errors as $error) {
            echo '<div class="error"><p>' . esc_html($error) . '</p></div>';
        }
    }
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
        .np-order-hub-import-stores{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 16px;margin-top:8px;}
        .np-order-hub-import-stores label{display:flex;align-items:center;gap:8px;}
        .np-order-hub-import-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;}
        .np-order-hub-debug{margin:16px 0;padding:12px;border:1px solid #dcdcde;background:#fff;}
        .np-order-hub-debug summary{cursor:pointer;font-weight:600;}
        .np-order-hub-debug pre{white-space:pre-wrap;margin:8px 0 0;max-height:320px;overflow:auto;background:#f6f7f7;padding:8px;border:1px solid #dcdcde;}
    </style>';

    echo '<form method="post" style="margin:12px 0 8px;">';
    wp_nonce_field('np_order_hub_import_revenue');
    echo '<div>';
    echo '<button class="button" type="submit" name="np_order_hub_import_revenue" value="1">Import historical revenue</button>';
    echo ' <label style="margin-left:8px;"><input type="checkbox" name="np_order_hub_import_debug" value="1"' . (!empty($_POST['np_order_hub_import_debug']) ? ' checked' : '') . '> Debug</label>';
    echo '</div>';
    echo '<p class="description" style="margin-top:8px;">Velg hvilke butikker som skal importeres. Bruker WooCommerce API og henter omsetning før første ordre mottatt i huben.</p>';
    if (!empty($importable_store_options)) {
        echo '<div class="np-order-hub-import-actions">';
        echo '<button type="button" class="button" id="np-order-hub-import-select-all">Velg alle</button>';
        echo '<button type="button" class="button" id="np-order-hub-import-clear-all">Fjern alle</button>';
        echo '</div>';
        echo '<div class="np-order-hub-import-stores">';
        foreach ($importable_store_options as $key => $label) {
            $checked = in_array($key, $selected_import_stores, true) ? ' checked' : '';
            echo '<label><input type="checkbox" name="np_order_hub_import_stores[]" value="' . esc_attr($key) . '"' . $checked . '> ' . esc_html($label) . '</label>';
        }
        echo '</div>';
    } else {
        echo '<p class="description" style="margin-top:8px;">Alle butikker har allerede historisk omsetning.</p>';
    }
    echo '</form>';

    if (np_order_hub_revenue_debug_enabled()) {
        $debug = np_order_hub_revenue_debug_get();
        if (!empty($debug)) {
            echo '<details class="np-order-hub-debug" open>';
            echo '<summary>Import debug</summary>';
            foreach ($debug as $store_key => $entries) {
                $title = isset($store_options[$store_key]) ? $store_options[$store_key] : $store_key;
                echo '<h4 style="margin:10px 0 4px;">' . esc_html($title) . '</h4>';
                echo '<pre>' . esc_html(wp_json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
            }
            echo '</details>';
        }
    }

    if (!empty($importable_store_options)) {
        echo '<script>
            (function(){
                var selectAll = document.getElementById("np-order-hub-import-select-all");
                var clearAll = document.getElementById("np-order-hub-import-clear-all");
                var boxes = document.querySelectorAll("input[name=\'np_order_hub_import_stores[]\']");
                if (selectAll) {
                    selectAll.addEventListener("click", function(){
                        boxes.forEach(function(box){ box.checked = true; });
                    });
                }
                if (clearAll) {
                    clearAll.addEventListener("click", function(){
                        boxes.forEach(function(box){ box.checked = false; });
                    });
                }
            })();
        </script>';
    }

    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-revenue" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-store">Store</label>';
    echo '<select id="np-order-hub-revenue-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-date-from">From</label>';
    echo '<input id="np-order-hub-revenue-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-date-to">To</label>';
    echo '<input id="np-order-hub-revenue-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Omsetning totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Gross revenue</span><strong>' . esc_html($total_display) . '</strong></div>';
    if (!$include_history && !empty($history)) {
        echo '<p class="description" style="margin-top:8px;">Historisk omsetning er skjult når du bruker datofilter.</p>';
    } elseif ($include_history && !empty($history)) {
        $history_display = np_order_hub_format_money($history_total, $currency_label);
        echo '<div class="np-order-hub-card-row"><span>Historisk</span><strong>' . esc_html($history_display) . '</strong></div>';
    }
    if ($has_multiple_currencies) {
        echo '<p class="description" style="margin-top:8px;">Flere valutaer i resultatet.</p>';
    }
    echo '</div>';

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Gross revenue</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($rows)) {
        echo '<tr><td colspan="3">Ingen ordre funnet.</td></tr>';
    } else {
        foreach ($rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_display = np_order_hub_format_money($row_total, $row_currency);

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
}

function np_order_hub_notifications_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $notice = '';
    if (!empty($_POST['np_order_hub_save_notifications']) && check_admin_referer('np_order_hub_save_notifications')) {
        $enabled = !empty($_POST['np_order_hub_pushover_enabled']);
        $user_key = sanitize_text_field((string) ($_POST['np_order_hub_pushover_user'] ?? ''));
        $token = sanitize_text_field((string) ($_POST['np_order_hub_pushover_token'] ?? ''));
        $title = sanitize_text_field((string) ($_POST['np_order_hub_pushover_title'] ?? 'Order Hub'));
        $logo_enabled = !empty($_POST['np_order_hub_pushover_logo_enabled']);
        $logo_url = esc_url_raw((string) ($_POST['np_order_hub_pushover_logo'] ?? ''));

        update_option(NP_ORDER_HUB_PUSHOVER_ENABLED_OPTION, $enabled ? '1' : '0');
        update_option(NP_ORDER_HUB_PUSHOVER_USER_OPTION, $user_key);
        update_option(NP_ORDER_HUB_PUSHOVER_TOKEN_OPTION, $token);
        update_option(NP_ORDER_HUB_PUSHOVER_TITLE_OPTION, $title);
        update_option(NP_ORDER_HUB_PUSHOVER_LOGO_ENABLED_OPTION, $logo_enabled ? '1' : '0');
        update_option(NP_ORDER_HUB_PUSHOVER_LOGO_OPTION, $logo_url);
        $notice = 'Settings saved.';
    }

    $settings = np_order_hub_get_pushover_settings();

    echo '<div class="wrap">';
    echo '<h1>Varsler</h1>';
    if ($notice !== '') {
        echo '<div class="updated"><p>' . esc_html($notice) . '</p></div>';
    }
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_save_notifications');
    echo '<table class="form-table">';
    echo '<tr><th scope="row">Enable Pushover</th><td>';
    echo '<label><input type="checkbox" name="np_order_hub_pushover_enabled" value="1"' . checked($settings['enabled'], true, false) . ' /> Send notifications for new orders</label>';
    echo '</td></tr>';
    echo '<tr><th scope="row">Logo attachment</th><td>';
    echo '<label><input type="checkbox" name="np_order_hub_pushover_logo_enabled" value="1"' . checked(!empty($settings['logo_enabled']), true, false) . ' /> Attach logo image to push notifications</label>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-user">User key</label></th>';
    echo '<td><input id="np-order-hub-pushover-user" name="np_order_hub_pushover_user" type="text" class="regular-text" value="' . esc_attr($settings['user']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-token">App token</label></th>';
    echo '<td><input id="np-order-hub-pushover-token" name="np_order_hub_pushover_token" type="text" class="regular-text" value="' . esc_attr($settings['token']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-title">Title</label></th>';
    echo '<td><input id="np-order-hub-pushover-title" name="np_order_hub_pushover_title" type="text" class="regular-text" value="' . esc_attr($settings['title']) . '" />';
    echo '<p class="description">Set the Pushover application icon/logo in your Pushover app settings.</p>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-logo">Logo URL</label></th>';
    echo '<td><input id="np-order-hub-pushover-logo" name="np_order_hub_pushover_logo" type="url" class="regular-text" value="' . esc_attr($settings['logo_url']) . '" />';
    echo '<p class="description">Optional. Upload logo to Media Library and paste the URL. Leave blank to use the default Nordic logo.</p>';
    echo '</td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_save_notifications" value="1">Save settings</button></p>';
    echo '</form>';
    echo '</div>';
}

function np_order_hub_revenue_dashboard_shortcode($atts) {
    $atts = shortcode_atts(array(
        'capability' => 'manage_options',
        'refresh' => '',
        'private' => '0',
        'debug' => '0',
    ), $atts, 'np_order_hub_revenue_dashboard');

    $private_raw = strtolower(trim((string) $atts['private']));
    $require_auth = in_array($private_raw, array('1', 'true', 'yes', 'y', 'on'), true);
    $debug_raw = strtolower(trim((string) $atts['debug']));
    $debug_enabled = in_array($debug_raw, array('1', 'true', 'yes', 'y', 'on'), true);
    $capability = sanitize_key((string) $atts['capability']);
    if ($capability === '') {
        $capability = 'manage_options';
    }
    $can_view = true;
    if ($require_auth) {
        $can_view = current_user_can($capability);
    }
    if (!$can_view) {
        if ($debug_enabled) {
            $debug = array(
                'private_raw' => $private_raw,
                'require_auth' => $require_auth,
                'capability' => $capability,
                'is_user_logged_in' => is_user_logged_in(),
                'current_user_can' => $can_view,
                'time' => current_time('mysql'),
            );
            return '<pre class="np-order-hub-debug-box">' . esc_html(wp_json_encode($debug, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
        }
        return '<p>Ingen tilgang.</p>';
    }

    $period_input = isset($_GET['np_period']) ? $_GET['np_period'] : 'daily';
    $custom_from = isset($_GET['np_from']) ? $_GET['np_from'] : '';
    $custom_to = isset($_GET['np_to']) ? $_GET['np_to'] : '';
    $range = np_order_hub_get_period_date_range($period_input, $custom_from, $custom_to);
    $filters = array(
        'store' => '',
        'status' => '',
        'search' => '',
        'date_from_raw' => $range['from'],
        'date_to_raw' => $range['to'],
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);

    $rows = np_order_hub_query_revenue_by_store($filters);
    $totals = np_order_hub_query_revenue_totals($filters);

    if (!empty($rows)) {
        usort($rows, function ($a, $b) {
            $store_cmp = strcmp((string) ($a['store_name'] ?? ''), (string) ($b['store_name'] ?? ''));
            if ($store_cmp !== 0) {
                return $store_cmp;
            }
            return strcmp((string) ($a['store_key'] ?? ''), (string) ($b['store_key'] ?? ''));
        });
    }

    $currency_label = '';
    $has_multiple_currencies = false;
    if (!empty($rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $rows))));
        $currency_count = count($currencies);
        if ($currency_count === 1) {
            $currency_label = (string) $currencies[0];
        }
        $has_multiple_currencies = $currency_count > 1;
    }

    $now = current_time('timestamp');
    $month_name = np_order_hub_get_norwegian_month_name($now);
    $prev_month_ts = strtotime('first day of last month', $now);
    $prev_month_name = np_order_hub_get_norwegian_month_name($prev_month_ts);
    $period_labels = array(
        'daily' => 'Daglig',
        'month_current' => 'Denne måneden',
        'month_previous' => 'Forrige måned',
        'yearly' => 'Årlig',
        'custom' => 'Valgt periode',
    );
    $period_label = isset($period_labels[$range['period']]) ? $period_labels[$range['period']] : 'Daglig';

    $current_url = home_url(add_query_arg(array(), wp_unslash($_SERVER['REQUEST_URI'])));
    $base_url = remove_query_arg(array('np_period', 'np_from', 'np_to'), $current_url);
    $period_urls = array(
        'daily' => add_query_arg('np_period', 'daily', $base_url),
        'month_current' => add_query_arg('np_period', 'month_current', $base_url),
        'month_previous' => add_query_arg('np_period', 'month_previous', $base_url),
        'yearly' => add_query_arg('np_period', 'yearly', $base_url),
    );

    $refresh_seconds = is_numeric($atts['refresh']) ? (int) $atts['refresh'] : 0;
    if ($refresh_seconds < 0) {
        $refresh_seconds = 0;
    }
    $custom_from_value = $range['from'];
    $custom_to_value = $range['to'];

    ob_start();
    echo '<div class="np-order-hub-revenue-dashboard">';
    $period_links = array();
    $yearly_link = '';
    foreach ($period_urls as $key => $url) {
        $active = $range['period'] === $key ? ' is-active' : '';
        $label = isset($period_labels[$key]) ? $period_labels[$key] : $key;
        $link_html = '<a class="np-order-hub-period' . ($key === 'yearly' ? ' np-order-hub-period-yearly' : '') . $active . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
        if ($key === 'yearly') {
            $yearly_link = $link_html;
        } else {
            $period_links[] = $link_html;
        }
    }

    echo '<div class="np-order-hub-revenue-toolbar">';
    echo '<div class="np-order-hub-revenue-controls">' . implode('', $period_links) . '</div>';
    if ($yearly_link !== '') {
        echo $yearly_link;
    }
    echo '<form class="np-order-hub-custom-range" method="get" action="' . esc_url($base_url) . '">';
    echo '<input type="hidden" name="np_period" value="custom" />';
    echo '<span class="np-order-hub-custom-label">Velg periode</span>';
    echo '<div class="np-order-hub-custom-fields">';
    echo '<input type="date" name="np_from" placeholder="29.01.26" value="' . esc_attr($custom_from_value) . '" />';
    echo '<span>til</span>';
    echo '<input type="date" name="np_to" placeholder="29.01.26" value="' . esc_attr($custom_to_value) . '" />';
    echo '<button type="submit">Vis</button>';
    echo '</div>';
    echo '</form>';
    echo '</div>';
    // Period meta hidden on request.

    $total_display = np_order_hub_format_money((float) $totals['total'], $currency_label);
    $total_orders = isset($totals['count']) ? (int) $totals['count'] : 0;
    $total_items = isset($item_counts['total_items']) ? (int) $item_counts['total_items'] : 0;
    $avg_order_value = $total_orders > 0 ? ((float) $totals['total'] / $total_orders) : 0.0;
    $avg_order_display = np_order_hub_format_money($avg_order_value, $currency_label);
    $avg_items_value = $total_orders > 0 ? ($total_items / $total_orders) : 0.0;
    $avg_items_display = number_format($avg_items_value, 1, ',', ' ');
    echo '<div class="np-order-hub-revenue-metrics">';
    echo '<div class="np-order-hub-metric np-order-hub-metric-primary"><div class="np-order-hub-metric-label">Omsetning</div><div class="np-order-hub-metric-value">' . esc_html($total_display) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Ordre</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_orders) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Plagg</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_items) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt ordre</div><div class="np-order-hub-metric-value">' . esc_html($avg_order_display) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt plagg</div><div class="np-order-hub-metric-value">' . esc_html($avg_items_display) . '</div></div>';
    echo '</div>';
    echo '<button type="button" class="np-order-hub-metrics-toggle" aria-expanded="false"><span>Se mer</span></button>';
    if ($has_multiple_currencies) {
        echo '<p class="np-order-hub-multi-currency">Flere valutaer i resultatet.</p>';
    }

    echo '<table class="np-order-hub-revenue-table">';
    echo '<thead><tr><th>Butikk</th><th>Omsetning</th><th>Ordre</th><th>Plagg</th><th>Snitt ordre</th><th>Snitt plagg</th></tr></thead>';
    echo '<tbody>';
    if (empty($rows)) {
        echo '<tr><td colspan="6">Ingen ordre funnet.</td></tr>';
    } else {
        foreach ($rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $store_key = isset($row['store_key']) ? sanitize_key((string) $row['store_key']) : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_items = $store_key !== '' && isset($items_by_store[$store_key]) ? (int) $items_by_store[$store_key] : 0;
            $row_display = np_order_hub_format_money($row_total, $row_currency);
            $avg_value = $row_count > 0 ? ($row_total / $row_count) : 0.0;
            $avg_display = np_order_hub_format_money($avg_value, $row_currency);
            $avg_items = $row_count > 0 ? ($row_items / $row_count) : 0.0;
            $avg_items_display = number_format($avg_items, 1, '.', '');

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html((string) $row_items) . '</td>';
            echo '<td>' . esc_html($avg_display) . '</td>';
            echo '<td>' . esc_html($avg_items_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';
    echo '</div>';

    echo '<style>
        .np-order-hub-revenue-dashboard{width:85vw;max-width:85vw;margin:24px auto;font-family:inherit;box-sizing:border-box;margin-left:calc(50% - 42.5vw);margin-right:calc(50% - 42.5vw);}
        .np-order-hub-revenue-toolbar{display:flex;flex-wrap:nowrap;gap:12px;align-items:center;margin:8px 0 6px;overflow-x:auto;}
        .np-order-hub-revenue-controls{display:flex;gap:8px;flex-wrap:nowrap;margin:0;white-space:nowrap;order:1;}
        .np-order-hub-period{padding:8px 14px;border:1px solid #d0d6e1;border-radius:8px;text-decoration:none;color:#1f2937;background:#fff;}
        .np-order-hub-period.is-active{background:#111827;color:#fff;border-color:#111827;}
        .np-order-hub-period-yearly{order:2;white-space:nowrap;}
        .np-order-hub-period-meta{color:#6b7280;margin:0 0 16px;}
        .np-order-hub-custom-range{order:3;margin:0 0 0 auto;display:flex;align-items:center;gap:8px;flex-wrap:nowrap;white-space:nowrap;justify-content:flex-end;text-align:right;}
        .np-order-hub-custom-label{font-weight:600;color:#1f2937;}
        .np-order-hub-custom-fields{display:flex;flex-wrap:nowrap;gap:8px;align-items:center;}
        .np-order-hub-custom-fields input[type="date"]{padding:6px 8px;border:1px solid #d0d6e1;border-radius:6px;}
        .np-order-hub-custom-fields button{padding:6px 12px;border-radius:6px;border:1px solid #111827;background:#111827;color:#fff;cursor:pointer;}
        .np-order-hub-revenue-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:30px 0;}
        .np-order-hub-metric{display:flex;flex-direction:column;gap:4px;align-items:flex-start;background:#f8f9fc;border:1px solid #e5e7eb;border-radius:12px;padding:16px 20px;}
        .np-order-hub-metric-value{font-size:24px;font-weight:700;}
        .np-order-hub-metric-label{color:#6b7280;}
        .np-order-hub-metrics-toggle{display:none;align-items:center;justify-content:space-between;gap:8px;width:100%;padding:12px 16px;border-radius:12px;border:1px solid #e5e7eb;background:#fff;color:#111827;font-weight:600;cursor:pointer;}
        .np-order-hub-metrics-toggle::after{content:"↓";font-size:16px;line-height:1;}
        .np-order-hub-metrics-toggle[aria-expanded="true"]::after{content:"↑";}
        .np-order-hub-multi-currency{color:#b45309;margin:0 0 12px;}
        .np-order-hub-revenue-table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;}
        .np-order-hub-revenue-table th,
        .np-order-hub-revenue-table td{padding:12px 14px;border-bottom:1px solid #eef2f7;text-align:left;}
        .np-order-hub-revenue-table th{background:#f8fafc;font-weight:600;}
        .np-order-hub-revenue-table tbody tr:last-child td{border-bottom:none;}
        .np-order-hub-debug-box{white-space:pre-wrap;background:#111827;color:#e5e7eb;padding:12px;border-radius:8px;font-size:12px;}
        @media (max-width:768px){
            .np-order-hub-revenue-dashboard{font-size:12px;width:100%;max-width:100%;margin:0 auto;box-sizing:border-box;padding:0;}
            .np-order-hub-revenue-dashboard *{font-size:12px;}
            .np-order-hub-revenue-toolbar{display:grid;grid-template-columns:auto 1fr;align-items:center;gap:8px 10px;overflow-x:visible;}
            .np-order-hub-period-yearly{order:0;grid-column:1;}
            .np-order-hub-custom-range{order:0;grid-column:2;justify-self:stretch;width:100%;}
            .np-order-hub-revenue-controls{order:1;grid-column:1 / -1;flex-wrap:wrap;width:100%;}
            .np-order-hub-custom-label{display:none;}
            .np-order-hub-custom-fields{width:100%;display:grid;grid-template-columns:1fr auto 1fr auto;gap:6px;align-items:center;}
            .np-order-hub-custom-fields input[type="date"]{width:100%;min-width:0;}
            .np-order-hub-custom-fields button{padding:6px 10px;}
            .np-order-hub-revenue-metrics{grid-template-columns:1fr;}
            .np-order-hub-metric{width:100%;flex-direction:row;align-items:center;justify-content:space-between;}
            .np-order-hub-metric-value{font-size:14px;}
            .np-order-hub-metric-label{font-size:12px;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric{display:none;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric-primary{display:flex;}
            .np-order-hub-metrics-toggle{display:flex;}
            .np-order-hub-revenue-table{display:block;overflow-x:auto;width:100%;}
            .np-order-hub-revenue-total{width:100%;}
        }
    </style>';
    if ($refresh_seconds > 0) {
        echo '<script>
            (function(){
                var refreshMs = ' . (int) $refresh_seconds . ' * 1000;
                if (refreshMs > 0) {
                    setTimeout(function(){ window.location.reload(); }, refreshMs);
                }
            })();
        </script>';
    }
    echo '<script>
        (function(){
            var roots = document.querySelectorAll(".np-order-hub-revenue-dashboard");
            if (!roots.length) { return; }
            roots.forEach(function(root){
                var metrics = root.querySelector(".np-order-hub-revenue-metrics");
                var toggle = root.querySelector(".np-order-hub-metrics-toggle");
                if (!metrics || !toggle) { return; }
                var label = toggle.querySelector("span");
                var setState = function(expanded){
                    metrics.classList.toggle("is-expanded", expanded);
                    toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
                    if (label) {
                        label.textContent = expanded ? "Se mindre" : "Se mer";
                    }
                };
                setState(false);
                toggle.addEventListener("click", function(){
                    setState(!metrics.classList.contains("is-expanded"));
                });
            });
        })();
    </script>';

    return ob_get_clean();
}

add_shortcode('np_order_hub_revenue_dashboard', 'np_order_hub_revenue_dashboard_shortcode');

function np_order_hub_help_scout_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $notice = '';
    $notice_type = 'updated';
    $current_user_id = get_current_user_id();
    $redirect_url = np_order_hub_help_scout_get_redirect_url();

    $flash_key = 'np_order_hub_help_scout_notice_' . $current_user_id;
    $flash = get_transient($flash_key);
    if (is_array($flash) && !empty($flash['message'])) {
        $notice = (string) $flash['message'];
        $notice_type = !empty($flash['type']) && $flash['type'] === 'error' ? 'error' : 'updated';
        delete_transient($flash_key);
    }

    $settings = np_order_hub_get_help_scout_settings();

    if (!empty($_GET['help_scout_action'])) {
        $action = sanitize_key((string) $_GET['help_scout_action']);
        if ($action === 'connect') {
            check_admin_referer('np_order_hub_help_scout_connect');
            if ($settings['client_id'] === '' || $settings['client_secret'] === '') {
                set_transient($flash_key, array('type' => 'error', 'message' => 'Add App ID and App Secret first.'), 30);
                wp_safe_redirect($redirect_url);
                exit;
            }
            $state = wp_generate_password(12, false);
            set_transient('np_order_hub_help_scout_state_' . $current_user_id, $state, 10 * MINUTE_IN_SECONDS);
            $auth_url = add_query_arg(array(
                'client_id' => $settings['client_id'],
                'state' => $state,
            ), 'https://secure.helpscout.net/authentication/authorizeClientApplication');
            wp_redirect($auth_url);
            exit;
        }
        if ($action === 'disconnect') {
            check_admin_referer('np_order_hub_help_scout_disconnect');
            update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, '');
            update_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, '');
            update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0);
            set_transient($flash_key, array('type' => 'updated', 'message' => 'Help Scout disconnected.'), 30);
            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    if (!empty($_GET['code']) || !empty($_GET['error'])) {
        $state = sanitize_text_field((string) ($_GET['state'] ?? ''));
        $expected_state = get_transient('np_order_hub_help_scout_state_' . $current_user_id);
        delete_transient('np_order_hub_help_scout_state_' . $current_user_id);

        if (!empty($_GET['error'])) {
            $error_message = sanitize_text_field((string) ($_GET['error_description'] ?? 'Help Scout OAuth failed.'));
            set_transient($flash_key, array('type' => 'error', 'message' => $error_message), 30);
        } elseif (!$expected_state || $state !== $expected_state) {
            set_transient($flash_key, array('type' => 'error', 'message' => 'Help Scout OAuth state mismatch.'), 30);
        } else {
            $result = np_order_hub_help_scout_exchange_code($settings, sanitize_text_field((string) $_GET['code']));
            if (is_wp_error($result)) {
                set_transient($flash_key, array('type' => 'error', 'message' => $result->get_error_message()), 30);
            } else {
                set_transient($flash_key, array('type' => 'updated', 'message' => 'Help Scout connected.'), 30);
            }
        }

        wp_safe_redirect($redirect_url);
        exit;
    }

    if (!empty($_POST['np_order_hub_save_help_scout']) && check_admin_referer('np_order_hub_save_help_scout')) {
        $token = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_token'] ?? ''));
        $mailbox_id = absint($_POST['np_order_hub_help_scout_mailbox'] ?? 0);
        $status = sanitize_key((string) ($_POST['np_order_hub_help_scout_default_status'] ?? 'pending'));
        if (!in_array($status, array('active', 'pending', 'closed'), true)) {
            $status = 'pending';
        }
        $user_id = absint($_POST['np_order_hub_help_scout_user'] ?? 0);
        $client_id = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_client_id'] ?? ''));
        $client_secret = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_client_secret'] ?? ''));

        if ($token !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, $token);
        }
        update_option(NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION, $mailbox_id);
        update_option(NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION, $status);
        update_option(NP_ORDER_HUB_HELP_SCOUT_USER_OPTION, $user_id);
        if ($client_id !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION, $client_id);
        }
        if ($client_secret !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION, $client_secret);
        }

        $notice = 'Settings saved.';
        $notice_type = 'updated';
        $settings = np_order_hub_get_help_scout_settings();
    }

    $connected = ($settings['token'] !== '' || $settings['refresh_token'] !== '');
    $connect_url = wp_nonce_url(add_query_arg('help_scout_action', 'connect', $redirect_url), 'np_order_hub_help_scout_connect');
    $disconnect_url = wp_nonce_url(add_query_arg('help_scout_action', 'disconnect', $redirect_url), 'np_order_hub_help_scout_disconnect');

    echo '<div class="wrap">';
    echo '<h1>Help Scout</h1>';
    if ($notice !== '') {
        echo '<div class="' . esc_attr($notice_type) . '"><p>' . esc_html($notice) . '</p></div>';
    }
    echo '<p class="description">Redirect URL for the Help Scout app: <code>' . esc_html($redirect_url) . '</code></p>';
    echo '<p>';
    if ($connected) {
        echo '<span class="description" style="margin-right:12px;">Connected.</span>';
        echo '<a class="button" href="' . esc_url($disconnect_url) . '">Disconnect</a>';
    } else {
        echo '<a class="button button-primary" href="' . esc_url($connect_url) . '">Connect Help Scout</a>';
    }
    echo '</p>';

    echo '<form method="post">';
    wp_nonce_field('np_order_hub_save_help_scout');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-client-id">App ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-client-id" name="np_order_hub_help_scout_client_id" type="text" class="regular-text" value="' . esc_attr($settings['client_id']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-client-secret">App Secret</label></th>';
    echo '<td><input id="np-order-hub-help-scout-client-secret" name="np_order_hub_help_scout_client_secret" type="password" class="regular-text" value="" />';
    echo '<p class="description">Leave blank to keep the current secret.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-token">API token</label></th>';
    echo '<td><input id="np-order-hub-help-scout-token" name="np_order_hub_help_scout_token" type="password" class="regular-text" value="" />';
    echo '<p class="description">Optional. Use a personal access token if you prefer manual setup.</p></td></tr>';
    echo '<tr><th scope="row">Current access token</th><td>';
    if ($settings['token'] !== '') {
        echo '<input id="np-order-hub-help-scout-token-current" type="password" class="regular-text" value="' . esc_attr($settings['token']) . '" readonly /> ';
        echo '<button type="button" class="button" id="np-order-hub-help-scout-token-toggle">Show</button>';
        echo '<p class="description">OAuth access token stored in WordPress. Do not share.</p>';
    } else {
        echo '<span class="description">No token stored.</span>';
    }
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-mailbox">Mailbox ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-mailbox" name="np_order_hub_help_scout_mailbox" type="number" class="small-text" value="' . esc_attr((string) $settings['mailbox_id']) . '" />';
    echo '<p class="description">Find the mailbox ID in Help Scout settings or the URL.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-user">Sender user ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-user" name="np_order_hub_help_scout_user" type="number" class="small-text" value="' . esc_attr((string) $settings['user_id']) . '" />';
    echo '<p class="description">Required to send outbound email.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-status">Default status</label></th>';
    echo '<td><select id="np-order-hub-help-scout-status" name="np_order_hub_help_scout_default_status">';
    $status_options = array(
        'pending' => 'Pending',
        'active' => 'Active',
        'closed' => 'Closed',
    );
    foreach ($status_options as $key => $label) {
        $selected = selected($settings['default_status'], $key, false);
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select></td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_save_help_scout" value="1">Save settings</button></p>';
    echo '</form>';
    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var field = document.getElementById("np-order-hub-help-scout-token-current");
            var button = document.getElementById("np-order-hub-help-scout-token-toggle");
            if (!field || !button) {
                return;
            }
            button.addEventListener("click", function() {
                var showing = field.type === "text";
                field.type = showing ? "password" : "text";
                button.textContent = showing ? "Show" : "Hide";
            });
        });
    </script>';
    echo '</div>';
}

function np_order_hub_format_meta_lines($meta_data) {
    if (!is_array($meta_data)) {
        return array();
    }
    $lines = array();
    foreach ($meta_data as $meta) {
        if (!is_array($meta)) {
            continue;
        }
        $key = '';
        if (!empty($meta['display_key'])) {
            $key = (string) $meta['display_key'];
        } elseif (!empty($meta['key'])) {
            $key = (string) $meta['key'];
        }
        $key = trim($key);
        if ($key === '' || strpos($key, '_') === 0) {
            continue;
        }
        $value = '';
        if (isset($meta['display_value'])) {
            $value = $meta['display_value'];
        } elseif (isset($meta['value'])) {
            $value = $meta['value'];
        }
        if (is_array($value) || is_object($value)) {
            $value = wp_json_encode($value);
        }
        $value = trim((string) $value);
        if ($value === '') {
            continue;
        }
        $lines[] = $key . ': ' . $value;
    }
    return $lines;
}

function np_order_hub_order_details_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (!empty($_POST['np_order_hub_delete_record'])) {
        check_admin_referer('np_order_hub_delete_record');
        $delete_id = isset($_POST['record_id']) ? absint($_POST['record_id']) : 0;
        if ($delete_id > 0) {
            global $wpdb;
            $table = np_order_hub_table_name();
            $wpdb->delete($table, array('id' => $delete_id), array('%d'));
        }
        wp_safe_redirect(admin_url('admin.php?page=np-order-hub&np_order_hub_deleted=1'));
        exit;
    }

    $record_id = isset($_GET['record_id']) ? (int) $_GET['record_id'] : 0;
    $record = null;
    if ($record_id > 0) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $record = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM $table WHERE id = %d", $record_id),
            ARRAY_A
        );
    }

    $payload = array();
    if ($record && !empty($record['payload'])) {
        $decoded = json_decode($record['payload'], true);
        if (is_array($decoded)) {
            $payload = $decoded;
        }
    }
    $line_items = isset($payload['line_items']) && is_array($payload['line_items']) ? $payload['line_items'] : array();
    $help_scout_billing = isset($payload['billing']) && is_array($payload['billing']) ? $payload['billing'] : array();
    $help_scout_email = !empty($help_scout_billing['email']) ? sanitize_email((string) $help_scout_billing['email']) : '';
    $help_scout_first_name = !empty($help_scout_billing['first_name']) ? sanitize_text_field((string) $help_scout_billing['first_name']) : '';
    $help_scout_last_name = !empty($help_scout_billing['last_name']) ? sanitize_text_field((string) $help_scout_billing['last_name']) : '';

    $help_scout_notice = null;
    $help_scout_form = array(
        'subject' => '',
        'message' => '',
        'status' => '',
    );
    if ($record && !empty($_POST['np_order_hub_help_scout_send'])) {
        check_admin_referer('np_order_hub_help_scout_send');
        $help_scout_form['subject'] = sanitize_text_field((string) ($_POST['help_scout_subject'] ?? ''));
        $help_scout_form['message'] = sanitize_textarea_field((string) ($_POST['help_scout_message'] ?? ''));
        $help_scout_form['status'] = sanitize_key((string) ($_POST['help_scout_status'] ?? ''));
        $help_scout_settings = np_order_hub_get_help_scout_settings();
        $help_scout_statuses = array('active', 'pending', 'closed');

        if (!in_array($help_scout_form['status'], $help_scout_statuses, true)) {
            $help_scout_form['status'] = $help_scout_settings['default_status'];
        }

        if ($help_scout_settings['token'] === '' || empty($help_scout_settings['mailbox_id'])) {
            $help_scout_notice = array('type' => 'error', 'message' => 'Help Scout settings are missing. Add an API token and mailbox ID.', 'allow_html' => false);
        } elseif ($help_scout_email === '') {
            $help_scout_notice = array('type' => 'error', 'message' => 'Customer email is missing on this order.', 'allow_html' => false);
        } elseif ($help_scout_form['subject'] === '' || $help_scout_form['message'] === '') {
            $help_scout_notice = array('type' => 'error', 'message' => 'Subject and message are required.', 'allow_html' => false);
        } else {
            $customer = array('email' => $help_scout_email);
            if ($help_scout_first_name !== '') {
                $customer['firstName'] = $help_scout_first_name;
            }
            if ($help_scout_last_name !== '') {
                $customer['lastName'] = $help_scout_last_name;
            }

            $result = np_order_hub_help_scout_create_conversation(
                $help_scout_settings,
                $customer,
                $help_scout_form['subject'],
                $help_scout_form['status'],
                $help_scout_form['message']
            );
            if (is_wp_error($result)) {
                $help_scout_message = $result->get_error_message();
                $allow_html = false;
                $error_data = $result->get_error_data();
                if (is_array($error_data)) {
                    $request_body = isset($error_data['request_body']) ? (string) $error_data['request_body'] : '';
                    $request_headers = $error_data['request_headers'] ?? null;
                    $response_body = '';
                    if (isset($error_data['response_body'])) {
                        $response_body = (string) $error_data['response_body'];
                    } elseif (isset($error_data['body'])) {
                        $response_body = (string) $error_data['body'];
                    }
                    $response_headers = $error_data['response_headers'] ?? null;
                    $request_url = isset($error_data['request_url']) ? (string) $error_data['request_url'] : '';
                    if ($request_body !== '' || !empty($request_headers) || $response_body !== '' || !empty($response_headers)) {
                        $allow_html = true;
                        if ($request_url !== '') {
                            $help_scout_message .= ' <details><summary>Show request URL</summary><pre style="white-space:pre-wrap;">' . esc_html($request_url) . '</pre></details>';
                        }
                        if (!empty($request_headers)) {
                            $request_headers_text = is_string($request_headers) ? $request_headers : wp_json_encode($request_headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                            $help_scout_message .= ' <details><summary>Show request headers</summary><pre style="white-space:pre-wrap;">' . esc_html($request_headers_text) . '</pre></details>';
                        }
                        if ($request_body !== '') {
                            $help_scout_message .= ' <details><summary>Show request payload</summary><pre style="white-space:pre-wrap;">' . esc_html($request_body) . '</pre></details>';
                        }
                        if ($response_body !== '') {
                            $help_scout_message .= ' <details><summary>Show response body</summary><pre style="white-space:pre-wrap;">' . esc_html($response_body) . '</pre></details>';
                        }
                        if (!empty($response_headers)) {
                            $response_headers_text = is_string($response_headers) ? $response_headers : wp_json_encode($response_headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                            $help_scout_message .= ' <details><summary>Show response headers</summary><pre style="white-space:pre-wrap;">' . esc_html($response_headers_text) . '</pre></details>';
                        }
                    }
                }
                $help_scout_notice = array('type' => 'error', 'message' => $help_scout_message, 'allow_html' => $allow_html);
            } else {
                $message = 'Help Scout message sent to customer.';
                $allow_html = false;
                if (!empty($result['web_url'])) {
                    $message = 'Help Scout message sent. <a href="' . esc_url($result['web_url']) . '" target="_blank" rel="noopener">Open conversation</a>.';
                    $allow_html = true;
                }
                $help_scout_notice = array('type' => 'success', 'message' => $message, 'allow_html' => $allow_html);
                $help_scout_form = array('subject' => '', 'message' => '', 'status' => '');
            }
        }
    }

    $status_notice = null;
    if ($record && !empty($_POST['np_order_hub_update_status'])) {
        check_admin_referer('np_order_hub_update_status');
        $new_status = sanitize_key((string) $_POST['order_status']);
        $allowed_statuses = np_order_hub_get_allowed_statuses();
        if (!isset($allowed_statuses[$new_status])) {
            $status_notice = array('type' => 'error', 'message' => 'Invalid status selected.');
        } else {
            $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
            $result = np_order_hub_update_remote_order_status($store, (int) $record['order_id'], $new_status);
            if (is_wp_error($result)) {
                $status_notice = array('type' => 'error', 'message' => $result->get_error_message());
            } else {
                $record = np_order_hub_apply_local_status($record, $new_status);
                $status_notice = array('type' => 'success', 'message' => 'Order status updated.');
            }
        }
    }

    $delivery_notice = null;
    if ($record && !empty($_POST['np_order_hub_update_delivery_bucket'])) {
        check_admin_referer('np_order_hub_update_delivery_bucket');
        $bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? ''));
        $record = np_order_hub_update_delivery_bucket($record, $bucket);
        $delivery_notice = array('type' => 'success', 'message' => 'Delivery bucket updated.');
    }

    $reklamasjon_notice = null;
    $reklamasjon_open = false;
    $reklamasjon_allow_oos = false;
    $reklamasjon_popup_message = '';
    $reklamasjon_selected_items = array();
    $reklamasjon_qty_input = array();
    if ($record && !empty($_POST['np_order_hub_create_reklamasjon'])) {
        $reklamasjon_open = true;
        check_admin_referer('np_order_hub_create_reklamasjon');
        $reklamasjon_allow_oos = !empty($_POST['reklamasjon_allow_oos']);
        $selected_items = isset($_POST['reklamasjon_items']) ? array_map('absint', (array) $_POST['reklamasjon_items']) : array();
        $selected_items = array_values(array_filter($selected_items, function ($value) {
            return $value > 0;
        }));
        $reklamasjon_selected_items = $selected_items;
        if (empty($line_items)) {
            $reklamasjon_notice = array('type' => 'error', 'message' => 'No line items found for this order.', 'allow_html' => false);
        } elseif (empty($selected_items)) {
            $reklamasjon_notice = array('type' => 'error', 'message' => 'Select at least one item for the claim order.', 'allow_html' => false);
        } else {
            $items_by_id = array();
            foreach ($line_items as $item) {
                if (!is_array($item) || empty($item['id'])) {
                    continue;
                }
                $items_by_id[(int) $item['id']] = $item;
            }

            $qty_input = isset($_POST['reklamasjon_qty']) && is_array($_POST['reklamasjon_qty']) ? $_POST['reklamasjon_qty'] : array();
            $reklamasjon_qty_input = $qty_input;
            $items_payload = array();
            $errors = array();
            foreach ($selected_items as $item_id) {
                if (empty($items_by_id[$item_id])) {
                    $errors[] = 'Selected item not found.';
                    continue;
                }
                $source = $items_by_id[$item_id];
                $max_qty = isset($source['quantity']) ? (int) $source['quantity'] : 0;
                $requested_qty = isset($qty_input[$item_id]) ? absint($qty_input[$item_id]) : $max_qty;
                if ($max_qty < 1 || $requested_qty < 1 || $requested_qty > $max_qty) {
                    $errors[] = 'Invalid quantity selected for one or more items.';
                    continue;
                }
                $items_payload[] = array(
                    'item_id' => (int) $item_id,
                    'quantity' => (int) $requested_qty,
                );
            }

            if (!empty($errors)) {
                $reklamasjon_notice = array('type' => 'error', 'message' => $errors[0], 'allow_html' => false);
            } elseif (empty($items_payload)) {
                $reklamasjon_notice = array('type' => 'error', 'message' => 'No valid items were selected.', 'allow_html' => false);
            } else {
                $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
                $result = np_order_hub_create_remote_reklamasjon_order($store, (int) $record['order_id'], $items_payload, $reklamasjon_allow_oos);
                if (is_wp_error($result)) {
                    if ($result->get_error_code() === 'stock_unavailable') {
                        $reklamasjon_popup_message = 'Produktet er utsolgt. Opprette reklamasjon og sette som restordre?';
                        $reklamasjon_notice = array('type' => 'error', 'message' => $result->get_error_message(), 'allow_html' => false);
                    } else {
                        $reklamasjon_notice = array('type' => 'error', 'message' => $result->get_error_message(), 'allow_html' => false);
                    }
                } else {
                    $new_order_id = isset($result['order_id']) ? (int) $result['order_id'] : 0;
                    $new_order_number = isset($result['order_number']) ? (string) $result['order_number'] : '';
                    $message = 'Claim order created.';
                    if ($new_order_id > 0) {
                        $label = $new_order_number !== '' ? ('#' . $new_order_number) : ('#' . $new_order_id);
                        $open_url = np_order_hub_build_admin_order_url($store, $new_order_id);
                        if ($open_url !== '') {
                            $message = 'Claim order created: <a href="' . esc_url($open_url) . '" target="_blank" rel="noopener">' . esc_html($label) . '</a>.';
                        } else {
                            $message = 'Claim order created: ' . esc_html($label) . '.';
                        }
                    }
                    $reklamasjon_notice = array('type' => 'success', 'message' => $message, 'allow_html' => true);
                }
            }
        }
    }

    echo '<div class="wrap">';
    echo '<h1>Order Details</h1>';
    echo '<p><a href="' . esc_url(admin_url('admin.php?page=np-order-hub')) . '">&larr; Back to orders</a></p>';

    if (!empty($status_notice) && is_array($status_notice)) {
        $type = $status_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($status_notice['message']) ? (string) $status_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }

    if (!empty($delivery_notice) && is_array($delivery_notice)) {
        $type = $delivery_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($delivery_notice['message']) ? (string) $delivery_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }

    if (!empty($reklamasjon_notice) && is_array($reklamasjon_notice)) {
        $type = $reklamasjon_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($reklamasjon_notice['message']) ? (string) $reklamasjon_notice['message'] : '';
        if ($message !== '') {
            if (!empty($reklamasjon_notice['allow_html'])) {
                echo '<div class="' . esc_attr($type) . '"><p>' . wp_kses_post($message) . '</p></div>';
            } else {
                echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
            }
        }
    }

    if (!empty($help_scout_notice) && is_array($help_scout_notice)) {
        $type = $help_scout_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($help_scout_notice['message']) ? (string) $help_scout_notice['message'] : '';
        if ($message !== '') {
            if (!empty($help_scout_notice['allow_html'])) {
                echo '<div class="' . esc_attr($type) . '"><p>' . wp_kses_post($message) . '</p></div>';
            } else {
                echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
            }
        }
    }

    if (!$record) {
        echo '<div class="error"><p>Order not found.</p></div>';
        echo '</div>';
        return;
    }

    $order_label = $record['order_number'] !== '' ? ('#' . $record['order_number']) : ('#' . $record['order_id']);
    $date_label = '';
    if (!empty($record['date_created_gmt']) && $record['date_created_gmt'] !== '0000-00-00 00:00:00') {
        $date_label = get_date_from_gmt($record['date_created_gmt'], 'd.m.y');
    }
    $status_label = $record['status'] !== '' ? ucwords(str_replace('-', ' ', $record['status'])) : '';
    $currency = $record['currency'] !== '' ? $record['currency'] : (isset($payload['currency']) ? (string) $payload['currency'] : '');
    $total = isset($payload['total']) ? (float) $payload['total'] : (float) $record['total'];
    $total_display = trim(number_format_i18n($total, 2) . ' ' . $currency);

    echo '<div class="card" style="max-width: 900px; padding: 16px;">';
    echo '<h2 style="margin-top:0;">Order ' . esc_html($order_label) . '</h2>';
    echo '<p><strong>Store:</strong> ' . esc_html($record['store_name']) . '</p>';
    if ($date_label !== '') {
        echo '<p><strong>Date:</strong> ' . esc_html($date_label) . '</p>';
    }
    if ($status_label !== '') {
        echo '<p><strong>Status:</strong> ' . esc_html($status_label) . '</p>';
    }
    $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
    $allowed_statuses = np_order_hub_get_allowed_statuses();
    if (!empty($allowed_statuses)) {
        $token_missing = np_order_hub_get_store_token($store) === '';
        echo '<form method="post" style="margin:12px 0;">';
        wp_nonce_field('np_order_hub_update_status');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<label for="np-order-hub-status-update" style="margin-right:6px;"><strong>Update status:</strong></label>';
        echo '<select name="order_status" id="np-order-hub-status-update">';
        foreach ($allowed_statuses as $key => $label) {
            $selected = selected($record['status'], $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select> ';
        echo '<button class="button" type="submit" name="np_order_hub_update_status" value="1">Update</button>';
        if ($token_missing) {
            echo '<p class="description" style="margin:6px 0 0;">Store token missing in hub store settings.</p>';
        }
        echo '</form>';
    }
    $delivery_bucket = np_order_hub_record_delivery_bucket($record);
    echo '<form method="post" style="margin:12px 0;">';
    wp_nonce_field('np_order_hub_update_delivery_bucket');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<label for="np-order-hub-delivery-bucket" style="margin-right:6px;"><strong>Delivery bucket:</strong></label>';
    echo '<select name="delivery_bucket" id="np-order-hub-delivery-bucket">';
    echo '<option value="standard"' . selected($delivery_bucket, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select> ';
    echo '<button class="button" type="submit" name="np_order_hub_update_delivery_bucket" value="1">Update</button>';
    echo '</form>';
    echo '<p><strong>Total:</strong> ' . esc_html($total_display) . '</p>';
    $packing_url = np_order_hub_build_packing_slip_url(
        $store,
        (int) $record['order_id'],
        (string) $record['order_number'],
        isset($record['payload']) ? $record['payload'] : null
    );
    if (!empty($record['order_admin_url']) || $packing_url !== '') {
        echo '<p>';
        if ($packing_url !== '') {
            echo '<a class="button" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a> ';
        }
        if (!empty($record['order_admin_url'])) {
            echo '<a class="button button-primary" href="' . esc_url($record['order_admin_url']) . '" target="_blank" rel="noopener">Open order in store</a>';
        }
        echo '</p>';
    }
    echo '<form method="post" style="margin-top:10px;">';
    wp_nonce_field('np_order_hub_delete_record');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_delete_record" value="1" onclick="return confirm(\'Remove this order from the hub?\');">Delete from hub</button>';
    echo '</form>';
    echo '</div>';

    $help_scout_settings = np_order_hub_get_help_scout_settings();
    $help_scout_subject_default = 'Order ' . $order_label;
    $help_scout_subject_value = $help_scout_form['subject'] !== '' ? $help_scout_form['subject'] : $help_scout_subject_default;
    $help_scout_message_value = $help_scout_form['message'];
    $help_scout_status_value = $help_scout_form['status'] !== '' ? $help_scout_form['status'] : $help_scout_settings['default_status'];
    $help_scout_status_labels = array(
        'pending' => 'Pending',
        'active' => 'Active',
        'closed' => 'Closed',
    );
    if (!isset($help_scout_status_labels[$help_scout_status_value])) {
        $help_scout_status_value = $help_scout_settings['default_status'];
    }

    echo '<h2>Help Scout</h2>';
    if ($help_scout_settings['token'] === '' || empty($help_scout_settings['mailbox_id'])) {
        $settings_url = admin_url('admin.php?page=np-order-hub-help-scout');
        echo '<p class="description">Add a Help Scout API token and mailbox ID in <a href="' . esc_url($settings_url) . '">Help Scout settings</a>.</p>';
    } elseif ($help_scout_email === '') {
        echo '<p class="description">Customer email is missing on this order.</p>';
    } else {
        echo '<p><strong>Customer:</strong> ' . esc_html($help_scout_email) . '</p>';
        echo '<form method="post" style="max-width: 900px;">';
        wp_nonce_field('np_order_hub_help_scout_send');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="form-table">';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-subject">Subject</label></th>';
        echo '<td><input id="np-order-hub-help-scout-subject" name="help_scout_subject" type="text" class="regular-text" value="' . esc_attr($help_scout_subject_value) . '" /></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-status">Status</label></th>';
        echo '<td><select id="np-order-hub-help-scout-status" name="help_scout_status">';
        foreach ($help_scout_status_labels as $key => $label) {
            $selected = selected($help_scout_status_value, $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-message">Message</label></th>';
        echo '<td><textarea id="np-order-hub-help-scout-message" name="help_scout_message" rows="6" class="large-text">' . esc_textarea($help_scout_message_value) . '</textarea></td></tr>';
        echo '</table>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_help_scout_send" value="1">Send message</button></p>';
        echo '</form>';
    }

    echo '<h2>Reklamasjon</h2>';
    $token_missing = np_order_hub_get_store_token($store) === '';
    if ($token_missing) {
        echo '<p>Store token missing in hub store settings.</p>';
    } elseif (empty($line_items)) {
        echo '<p>No line items found for this order.</p>';
    } else {
        echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
        echo '<input type="checkbox" id="np-order-hub-reklamasjon-toggle"' . ($reklamasjon_open ? ' checked' : '') . ' /> Reklamasjon';
        echo '</label>';
        echo '<div id="np-order-hub-reklamasjon-form" style="margin-top:12px;' . ($reklamasjon_open ? '' : ' display:none;') . '">';
        echo '<form method="post" style="max-width: 900px;">';
        wp_nonce_field('np_order_hub_create_reklamasjon');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th>Select</th>';
        echo '<th>Product</th>';
        echo '<th>Ordered Qty</th>';
        echo '<th>Claim Qty</th>';
        echo '<th>SKU</th>';
        echo '</tr></thead>';
        echo '<tbody>';
        foreach ($line_items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $item_id = isset($item['id']) ? (int) $item['id'] : 0;
            if ($item_id < 1) {
                continue;
            }
            $name = isset($item['name']) ? (string) $item['name'] : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $sku = isset($item['sku']) ? (string) $item['sku'] : '';
            $checked = in_array($item_id, $reklamasjon_selected_items, true) ? ' checked' : '';
            $qty_value = $qty;
            if (isset($reklamasjon_qty_input[$item_id])) {
                $posted_qty = absint($reklamasjon_qty_input[$item_id]);
                if ($posted_qty > 0) {
                    $qty_value = $posted_qty;
                }
            }

            echo '<tr>';
            echo '<td><input type="checkbox" name="reklamasjon_items[]" value="' . esc_attr((string) $item_id) . '"' . $checked . ' /></td>';
            echo '<td>' . esc_html($name !== '' ? $name : 'Item') . '</td>';
            echo '<td>' . esc_html((string) $qty) . '</td>';
            echo '<td><input type="number" name="reklamasjon_qty[' . esc_attr((string) $item_id) . ']" min="1" max="' . esc_attr((string) $qty) . '" value="' . esc_attr((string) $qty_value) . '" style="width:90px;" /></td>';
            echo '<td>' . esc_html($sku) . '</td>';
            echo '</tr>';
        }
        echo '</tbody>';
        echo '</table>';
        $allow_checked = $reklamasjon_allow_oos ? ' checked' : '';
        echo '<p style="margin-top:10px;">';
        echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
        echo '<input type="checkbox" name="reklamasjon_allow_oos" value="1"' . $allow_checked . ' /> Create even if out of stock (customer waiting for stock)';
        echo '</label>';
        echo '</p>';
        if ($reklamasjon_popup_message !== '') {
            echo '<input type="hidden" id="np-order-hub-reklamasjon-popup" value="' . esc_attr($reklamasjon_popup_message) . '" />';
        }
        echo '<p style="margin-top:12px;">';
        echo '<button class="button button-primary" type="submit" name="np_order_hub_create_reklamasjon" value="1">Create claim order</button>';
        echo '</p>';
        echo '</form>';
        echo '</div>';
        echo '<script>
            document.addEventListener("DOMContentLoaded", function() {
                var toggle = document.getElementById("np-order-hub-reklamasjon-toggle");
                var form = document.getElementById("np-order-hub-reklamasjon-form");
                if (!toggle || !form) {
                    return;
                }
                toggle.addEventListener("change", function() {
                    form.style.display = toggle.checked ? "block" : "none";
                });
                var popup = document.getElementById("np-order-hub-reklamasjon-popup");
                if (popup && popup.value) {
                    var innerForm = form.querySelector("form");
                    var allow = innerForm ? innerForm.querySelector("input[name=\'reklamasjon_allow_oos\']") : null;
                    if (innerForm && (!allow || !allow.checked)) {
                        if (window.confirm(popup.value)) {
                            if (allow) {
                                allow.checked = true;
                            }
                            innerForm.submit();
                        }
                    }
                }
            });
        </script>';
    }

    echo '<h2>Items</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Product</th>';
    echo '<th>Qty</th>';
    echo '<th>Line Total</th>';
    echo '<th>SKU</th>';
    echo '<th>Details</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($line_items)) {
        echo '<tr><td colspan="5">No line items found.</td></tr>';
    } else {
        foreach ($line_items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? (string) $item['name'] : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;
            $sku = isset($item['sku']) ? (string) $item['sku'] : '';
            $meta_lines = np_order_hub_format_meta_lines(isset($item['meta_data']) ? $item['meta_data'] : array());

            echo '<tr>';
            echo '<td>' . esc_html($name !== '' ? $name : 'Item') . '</td>';
            echo '<td>' . esc_html((string) $qty) . '</td>';
            echo '<td>' . esc_html(trim(number_format_i18n($line_total, 2) . ' ' . $currency)) . '</td>';
            echo '<td>' . esc_html($sku) . '</td>';
            if (!empty($meta_lines)) {
                echo '<td><ul style="margin:0; padding-left: 16px;">';
                foreach ($meta_lines as $line) {
                    echo '<li>' . esc_html($line) . '</li>';
                }
                echo '</ul></td>';
            } else {
                echo '<td></td>';
            }
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';
    echo '</div>';
}

function np_order_hub_reklamasjon_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_reklamasjon_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $reklamasjon_totals = np_order_hub_query_reklamasjon_totals(
        array('store' => $filters['store']),
        $filters['date_from'],
        $filters['date_to']
    );
    $reklamasjon_rows = np_order_hub_query_reklamasjon_by_store($filters);
    $orders = np_order_hub_query_reklamasjon_orders($filters, 500);

    $currency_label = '';
    if (!empty($reklamasjon_rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $reklamasjon_rows))));
        if (count($currencies) === 1) {
            $currency_label = (string) $currencies[0];
        }
    }

    $product_rows = array();
    foreach ($orders as $order) {
        if (!is_array($order)) {
            continue;
        }
        $payload = !empty($order['payload']) ? json_decode((string) $order['payload'], true) : null;
        if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
            continue;
        }
        $store_key = isset($order['store_key']) ? (string) $order['store_key'] : '';
        $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
        $currency = isset($order['currency']) ? (string) $order['currency'] : '';

        foreach ($payload['line_items'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? trim((string) $item['name']) : '';
            $sku = isset($item['sku']) ? trim((string) $item['sku']) : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;

            if ($qty < 1) {
                continue;
            }
            if ($name === '') {
                $name = 'Item';
            }
            $product_label = $sku !== '' ? ($name . ' (' . $sku . ')') : $name;
            $key = $store_key . '|' . $product_label;

            if (!isset($product_rows[$key])) {
                $product_rows[$key] = array(
                    'store_name' => $store_name !== '' ? $store_name : $store_key,
                    'product' => $product_label,
                    'qty' => 0,
                    'total' => 0.0,
                    'currency' => $currency,
                );
            }
            $product_rows[$key]['qty'] += $qty;
            $product_rows[$key]['total'] += $line_total;
            if ($product_rows[$key]['currency'] !== '' && $currency !== '' && $product_rows[$key]['currency'] !== $currency) {
                $product_rows[$key]['currency'] = '';
            }
        }
    }

    $product_rows = array_values($product_rows);
    usort($product_rows, function ($a, $b) {
        $store_cmp = strcmp((string) $a['store_name'], (string) $b['store_name']);
        if ($store_cmp !== 0) {
            return $store_cmp;
        }
        return strcmp((string) $a['product'], (string) $b['product']);
    });

    $base_url = admin_url('admin.php?page=np-order-hub-reklamasjon');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-reklamasjon-page">';
    echo '<h1>Reklamasjon</h1>';
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
    </style>';
    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-reklamasjon" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-store">Store</label>';
    echo '<select id="np-order-hub-rek-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-date-from">From</label>';
    echo '<input id="np-order-hub-rek-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-date-to">To</label>';
    echo '<input id="np-order-hub-rek-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $total_display = np_order_hub_format_money(
        isset($reklamasjon_totals['total']) ? (float) $reklamasjon_totals['total'] : 0.0,
        $currency_label
    );
    $count = isset($reklamasjon_totals['count']) ? (int) $reklamasjon_totals['count'] : 0;

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Reklamasjon totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
    echo '</div>';

    echo '<h2>Ordre</h2>';
    np_order_hub_render_order_list_table($orders, 'Ingen reklamasjon-ordre funnet.');

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($reklamasjon_rows)) {
        echo '<tr><td colspan="3">Ingen reklamasjon-ordre funnet.</td></tr>';
    } else {
        foreach ($reklamasjon_rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_display = np_order_hub_format_money($row_total, $row_currency);

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '<h2 style="margin-top:16px;">Produkter</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Produkt</th>';
    echo '<th>Antall</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($product_rows)) {
        echo '<tr><td colspan="4">Ingen reklamasjon-ordre funnet.</td></tr>';
    } else {
        foreach ($product_rows as $row) {
            $row_display = np_order_hub_format_money((float) $row['total'], (string) $row['currency']);
            echo '<tr>';
            echo '<td>' . esc_html($row['store_name']) . '</td>';
            echo '<td>' . esc_html($row['product']) . '</td>';
            echo '<td>' . esc_html((string) $row['qty']) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '</div>';
}

function np_order_hub_restordre_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_restordre_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $restordre_totals = np_order_hub_query_restordre_totals(
        array('store' => $filters['store']),
        $filters['date_from'],
        $filters['date_to']
    );
    $restordre_rows = np_order_hub_query_restordre_by_store($filters);
    $orders = np_order_hub_query_restordre_orders($filters, 500);

    $currency_label = '';
    if (!empty($restordre_rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $restordre_rows))));
        if (count($currencies) === 1) {
            $currency_label = (string) $currencies[0];
        }
    }

    $product_rows = array();
    foreach ($orders as $order) {
        if (!is_array($order)) {
            continue;
        }
        $payload = !empty($order['payload']) ? json_decode((string) $order['payload'], true) : null;
        if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
            continue;
        }
        $store_key = isset($order['store_key']) ? (string) $order['store_key'] : '';
        $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
        $currency = isset($order['currency']) ? (string) $order['currency'] : '';

        foreach ($payload['line_items'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? trim((string) $item['name']) : '';
            $sku = isset($item['sku']) ? trim((string) $item['sku']) : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;

            if ($qty < 1) {
                continue;
            }
            if ($name === '') {
                $name = 'Item';
            }
            $product_label = $sku !== '' ? ($name . ' (' . $sku . ')') : $name;
            $key = $store_key . '|' . $product_label;

            if (!isset($product_rows[$key])) {
                $product_rows[$key] = array(
                    'store_name' => $store_name !== '' ? $store_name : $store_key,
                    'product' => $product_label,
                    'qty' => 0,
                    'total' => 0.0,
                    'currency' => $currency,
                );
            }
            $product_rows[$key]['qty'] += $qty;
            $product_rows[$key]['total'] += $line_total;
            if ($product_rows[$key]['currency'] !== '' && $currency !== '' && $product_rows[$key]['currency'] !== $currency) {
                $product_rows[$key]['currency'] = '';
            }
        }
    }

    $product_rows = array_values($product_rows);
    usort($product_rows, function ($a, $b) {
        $store_cmp = strcmp((string) $a['store_name'], (string) $b['store_name']);
        if ($store_cmp !== 0) {
            return $store_cmp;
        }
        return strcmp((string) $a['product'], (string) $b['product']);
    });

    $base_url = admin_url('admin.php?page=np-order-hub-restordre');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-restordre-page">';
    echo '<h1>Restordre</h1>';
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
    </style>';
    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-restordre" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-store">Store</label>';
    echo '<select id="np-order-hub-rest-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-date-from">From</label>';
    echo '<input id="np-order-hub-rest-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-date-to">To</label>';
    echo '<input id="np-order-hub-rest-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $total_display = np_order_hub_format_money(
        isset($restordre_totals['total']) ? (float) $restordre_totals['total'] : 0.0,
        $currency_label
    );
    $count = isset($restordre_totals['count']) ? (int) $restordre_totals['count'] : 0;

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Restordre totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
    echo '</div>';

    echo '<h2>Ordre</h2>';
    np_order_hub_render_order_list_table($orders, 'Ingen restordre-ordre funnet.');

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($restordre_rows)) {
        echo '<tr><td colspan="3">Ingen restordre-ordre funnet.</td></tr>';
    } else {
        foreach ($restordre_rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_display = np_order_hub_format_money($row_total, $row_currency);

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '<h2 style="margin-top:16px;">Produkter</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Produkt</th>';
    echo '<th>Antall</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($product_rows)) {
        echo '<tr><td colspan="4">Ingen restordre-ordre funnet.</td></tr>';
    } else {
        foreach ($product_rows as $row) {
            $row_display = np_order_hub_format_money((float) $row['total'], (string) $row['currency']);
            echo '<tr>';
            echo '<td>' . esc_html($row['store_name']) . '</td>';
            echo '<td>' . esc_html($row['product']) . '</td>';
            echo '<td>' . esc_html((string) $row['qty']) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '</div>';
}

function np_order_hub_debug_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    global $wpdb;
    $table = np_order_hub_table_name();
    $records = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at_gmt DESC LIMIT 5", ARRAY_A);

    echo '<div class="wrap">';
    echo '<h1>Order Hub Debug</h1>';
    echo '<p>Shows the latest webhook payloads stored by the hub.</p>';

    if (empty($records)) {
        echo '<div class="notice notice-info"><p>No webhook payloads found yet.</p></div>';
        echo '</div>';
        return;
    }

    foreach ($records as $record) {
        $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
        $order_number = isset($record['order_number']) ? (string) $record['order_number'] : '';
        $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
        $store_key = isset($record['store_key']) ? (string) $record['store_key'] : '';
        $store_name = isset($record['store_name']) ? (string) $record['store_name'] : '';
        $created = '';
        if (!empty($record['created_at_gmt']) && $record['created_at_gmt'] !== '0000-00-00 00:00:00') {
            $created = get_date_from_gmt($record['created_at_gmt'], 'd.m.y');
        }
        $payload = array();
        if (!empty($record['payload'])) {
            $decoded = json_decode($record['payload'], true);
            if (is_array($decoded)) {
                $payload = $decoded;
            }
        }
        $store = np_order_hub_get_store_by_key($store_key);
        $access_key = $payload ? np_order_hub_extract_access_key($payload) : '';
        $packing_url = np_order_hub_build_packing_slip_url($store, $order_id, $order_number, $payload);
        $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $record['id']);

        echo '<div class="card" style="margin:16px 0; padding:16px;">';
        echo '<h2 style="margin:0 0 8px;">Order ' . esc_html($label) . '</h2>';
        if ($store_name !== '') {
            echo '<p><strong>Store:</strong> ' . esc_html($store_name) . '</p>';
        }
        if ($created !== '') {
            echo '<p><strong>Received:</strong> ' . esc_html($created) . '</p>';
        }
        echo '<p><strong>Access key:</strong> ' . esc_html($access_key !== '' ? $access_key : 'missing') . '</p>';
        echo '<p><strong>Packing slip URL:</strong> ' . ($packing_url !== '' ? '<code>' . esc_html($packing_url) . '</code>' : 'missing') . '</p>';
        echo '<p><a class="button" href="' . esc_url($details_url) . '">Open details</a></p>';

        $payload_text = '';
        if (!empty($payload)) {
            $payload_text = wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } elseif (!empty($record['payload'])) {
            $payload_text = (string) $record['payload'];
        }
        if ($payload_text === '') {
            $payload_text = 'Payload missing or could not be decoded.';
        }

        echo '<details style="margin-top:12px;">';
        echo '<summary>Payload</summary>';
        echo '<pre style="max-height:360px; overflow:auto; background:#f6f7f7; padding:12px; border:1px solid #dcdcde;">' . esc_html($payload_text) . '</pre>';
        echo '</details>';
        echo '</div>';
    }

    echo '</div>';
}

function np_order_hub_stores_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $stores = np_order_hub_get_stores();
    $edit_store = null;
    $connector_setup_key = np_order_hub_get_connector_setup_key(true);

    if (!empty($_POST['np_order_hub_connector_setup_action'])) {
        check_admin_referer('np_order_hub_connector_setup_key');
        $action = sanitize_key((string) $_POST['np_order_hub_connector_setup_action']);
        if ($action === 'regenerate') {
            $connector_setup_key = wp_generate_password(48, false, false);
            update_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, $connector_setup_key, false);
            echo '<div class="updated"><p>Connector setup key regenerated.</p></div>';
        } elseif ($action === 'save') {
            $candidate = trim((string) ($_POST['np_order_hub_connector_setup_key'] ?? ''));
            if ($candidate === '') {
                echo '<div class="error"><p>Connector setup key cannot be empty.</p></div>';
            } else {
                $connector_setup_key = $candidate;
                update_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, $connector_setup_key, false);
                echo '<div class="updated"><p>Connector setup key saved.</p></div>';
            }
        }
    }

    if (!empty($_POST['np_order_hub_update_store'])) {
        check_admin_referer('np_order_hub_update_store');
        $key = sanitize_key((string) ($_POST['store_key'] ?? ''));
        $existing = (isset($stores[$key]) && is_array($stores[$key])) ? $stores[$key] : null;
        $name = sanitize_text_field((string) ($_POST['store_name'] ?? ''));
        $url = esc_url_raw((string) ($_POST['store_url'] ?? ''));
        $secret = trim((string) ($_POST['store_secret'] ?? ''));
        $token = sanitize_text_field((string) ($_POST['store_token'] ?? ''));
        $consumer_key = sanitize_text_field((string) ($_POST['store_consumer_key'] ?? ''));
        $consumer_secret = sanitize_text_field((string) ($_POST['store_consumer_secret'] ?? ''));
        $packing_slip_url = np_order_hub_sanitize_url_template((string) ($_POST['packing_slip_url'] ?? (is_array($existing) && isset($existing['packing_slip_url']) ? $existing['packing_slip_url'] : '')));
        $type = sanitize_key((string) ($_POST['order_url_type'] ?? NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE));
        $type = $type === 'hpos' ? 'hpos' : 'legacy';
        $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? (is_array($existing) && isset($existing['delivery_bucket']) ? $existing['delivery_bucket'] : '')));
        $switch_date_raw = sanitize_text_field((string) ($_POST['delivery_bucket_switch_date'] ?? (is_array($existing) && isset($existing['delivery_bucket_switch_date']) ? $existing['delivery_bucket_switch_date'] : '')));
        $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
        $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($_POST['delivery_bucket_after'] ?? (is_array($existing) && isset($existing['delivery_bucket_after']) ? $existing['delivery_bucket_after'] : '')));

        if (!$existing) {
            echo '<div class="error"><p>Store not found.</p></div>';
        } else {
            $upsert = np_order_hub_store_upsert(array(
                'key' => $key,
                'name' => $name,
                'url' => $url,
                'secret' => $secret,
                'token' => $token,
                'consumer_key' => $consumer_key,
                'consumer_secret' => $consumer_secret,
                'packing_slip_url' => $packing_slip_url,
                'order_url_type' => $type,
                'delivery_bucket' => $delivery_bucket,
                'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
                'delivery_bucket_after' => $delivery_bucket_after,
            ));
            if (is_wp_error($upsert)) {
                $edit_store = array(
                    'key' => $key,
                    'name' => $name,
                    'url' => $url,
                    'secret' => $secret,
                    'token' => $token,
                    'consumer_key' => $consumer_key,
                    'consumer_secret' => $consumer_secret,
                    'packing_slip_url' => $packing_slip_url,
                    'order_url_type' => $type,
                    'delivery_bucket' => $delivery_bucket,
                    'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
                    'delivery_bucket_after' => $delivery_bucket_after,
                );
                echo '<div class="error"><p>' . esc_html($upsert->get_error_message()) . '</p></div>';
            } else {
                $stores = np_order_hub_get_stores();
                $edit_store = $upsert;
                echo '<div class="updated"><p>Store updated.</p></div>';
            }
        }
    }

    if (!empty($_POST['np_order_hub_add_store'])) {
        check_admin_referer('np_order_hub_add_store');
        $key = sanitize_key((string) $_POST['store_key']);
        $name = sanitize_text_field((string) $_POST['store_name']);
        $url = esc_url_raw((string) $_POST['store_url']);
        $secret = trim((string) $_POST['store_secret']);
        $token = sanitize_text_field((string) $_POST['store_token']);
        $consumer_key = sanitize_text_field((string) ($_POST['store_consumer_key'] ?? ''));
        $consumer_secret = sanitize_text_field((string) ($_POST['store_consumer_secret'] ?? ''));
        $packing_slip_url = np_order_hub_sanitize_url_template((string) ($_POST['packing_slip_url'] ?? ''));
        $type = sanitize_key((string) $_POST['order_url_type']);
        $type = $type === 'hpos' ? 'hpos' : 'legacy';
        $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? ''));
        $switch_date_raw = sanitize_text_field((string) ($_POST['delivery_bucket_switch_date'] ?? ''));
        $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
        $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($_POST['delivery_bucket_after'] ?? ''));

        $upsert = np_order_hub_store_upsert(array(
            'key' => $key,
            'name' => $name,
            'url' => $url,
            'secret' => $secret,
            'token' => $token,
            'consumer_key' => $consumer_key,
            'consumer_secret' => $consumer_secret,
            'packing_slip_url' => $packing_slip_url,
            'order_url_type' => $type,
            'delivery_bucket' => $delivery_bucket,
            'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
            'delivery_bucket_after' => $delivery_bucket_after,
        ));

        if (is_wp_error($upsert)) {
            echo '<div class="error"><p>' . esc_html($upsert->get_error_message()) . '</p></div>';
        } else {
            $stores = np_order_hub_get_stores();
            echo '<div class="updated"><p>Store saved.</p></div>';
        }
    }

    if (!empty($_GET['action']) && $_GET['action'] === 'delete_store' && !empty($_GET['store'])) {
        check_admin_referer('np_order_hub_delete_store');
        $store_key = sanitize_key((string) $_GET['store']);
        if (isset($stores[$store_key])) {
            unset($stores[$store_key]);
            np_order_hub_save_stores($stores);
            echo '<div class="updated"><p>Store removed.</p></div>';
        }
    }

    if ($edit_store === null && !empty($_GET['action']) && $_GET['action'] === 'edit_store' && !empty($_GET['store'])) {
        $store_key = sanitize_key((string) $_GET['store']);
        if (isset($stores[$store_key]) && is_array($stores[$store_key])) {
            $edit_store = $stores[$store_key];
        }
    }

    $webhook_base = rest_url('np-order-hub/v1/webhook');

    echo '<div class="wrap">';
    echo '<h1>Order Hub Stores</h1>';

    echo '<h2>Connector setup</h2>';
    echo '<p>Use this key in school network to auto-connect stores to Order Hub.</p>';
    echo '<form method="post" style="margin:12px 0 24px;">';
    wp_nonce_field('np_order_hub_connector_setup_key');
    echo '<input type="text" name="np_order_hub_connector_setup_key" class="regular-text" value="' . esc_attr($connector_setup_key) . '" />';
    echo '<button type="submit" class="button button-primary" name="np_order_hub_connector_setup_action" value="save" style="margin-left:8px;">Save key</button>';
    echo '<button type="submit" class="button" name="np_order_hub_connector_setup_action" value="regenerate" style="margin-left:8px;">Regenerate key</button>';
    echo '<p class="description">Endpoint: <code>' . esc_html(rest_url('np-order-hub/v1/store-connect')) . '</code></p>';
    echo '</form>';

    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Key</th>';
    echo '<th>URL</th>';
    echo '<th>Order URL Type</th>';
    echo '<th>Default Delivery</th>';
    echo '<th>Token</th>';
    echo '<th>API</th>';
    echo '<th>Webhook URL</th>';
    echo '<th>Actions</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($stores)) {
        echo '<tr><td colspan="9">No stores added yet.</td></tr>';
    } else {
        foreach ($stores as $store) {
            if (!is_array($store)) {
                continue;
            }
            $edit_url = admin_url('admin.php?page=np-order-hub-stores&action=edit_store&store=' . urlencode($store['key']));
            $delete_url = wp_nonce_url(
                admin_url('admin.php?page=np-order-hub-stores&action=delete_store&store=' . urlencode($store['key'])),
                'np_order_hub_delete_store'
            );
            $webhook_url = add_query_arg('store', $store['key'], $webhook_base);
            echo '<tr>';
            echo '<td>' . esc_html($store['name']) . '</td>';
            echo '<td>' . esc_html($store['key']) . '</td>';
            echo '<td><a href="' . esc_url($store['url']) . '" target="_blank" rel="noopener">' . esc_html($store['url']) . '</a></td>';
            echo '<td>' . esc_html($store['order_url_type'] === 'hpos' ? 'HPOS' : 'Legacy') . '</td>';
            $store_bucket = isset($store['delivery_bucket']) ? np_order_hub_normalize_delivery_bucket($store['delivery_bucket']) : 'standard';
            $bucket_label = $store_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
            $switch_date = isset($store['delivery_bucket_switch_date']) ? (string) $store['delivery_bucket_switch_date'] : '';
            $bucket_note = '';
            if ($switch_date !== '') {
                $after_bucket = isset($store['delivery_bucket_after']) ? np_order_hub_normalize_delivery_bucket_optional($store['delivery_bucket_after']) : '';
                if ($after_bucket === '') {
                    $after_bucket = $store_bucket === 'standard' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
                }
                $after_label = $after_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
                $bucket_note = ' (fra ' . $switch_date . ' → ' . $after_label . ')';
            }
            echo '<td>' . esc_html($bucket_label . $bucket_note) . '</td>';
            $token_label = !empty($store['token']) ? 'Configured' : '—';
            echo '<td>' . esc_html($token_label) . '</td>';
            $api_label = (!empty($store['consumer_key']) && !empty($store['consumer_secret'])) ? 'Configured' : '—';
            echo '<td>' . esc_html($api_label) . '</td>';
            echo '<td><code>' . esc_html($webhook_url) . '</code></td>';
            echo '<td><a class="button button-small" href="' . esc_url($edit_url) . '">Edit</a> <a class="button button-small" href="' . esc_url($delete_url) . '" onclick="return confirm(\'Remove this store?\')">Remove</a></td>';
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';

    $editing = is_array($edit_store);
    $store_key_value = $editing && isset($edit_store['key']) ? (string) $edit_store['key'] : '';
    $store_name_value = $editing && isset($edit_store['name']) ? (string) $edit_store['name'] : '';
    $store_url_value = $editing && isset($edit_store['url']) ? (string) $edit_store['url'] : '';
    $store_secret_value = $editing && isset($edit_store['secret']) ? (string) $edit_store['secret'] : '';
    $store_token_value = $editing && isset($edit_store['token']) ? (string) $edit_store['token'] : '';
    $store_consumer_key_value = $editing && isset($edit_store['consumer_key']) ? (string) $edit_store['consumer_key'] : '';
    $store_consumer_secret_value = $editing && isset($edit_store['consumer_secret']) ? (string) $edit_store['consumer_secret'] : '';
    $order_url_type_value = $editing && !empty($edit_store['order_url_type']) ? (string) $edit_store['order_url_type'] : NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE;
    $order_url_type_value = $order_url_type_value === 'hpos' ? 'hpos' : 'legacy';
    $delivery_bucket_value = $editing && isset($edit_store['delivery_bucket']) ? (string) $edit_store['delivery_bucket'] : 'standard';
    $delivery_bucket_value = np_order_hub_normalize_delivery_bucket($delivery_bucket_value);
    $delivery_bucket_switch_date_value = $editing && isset($edit_store['delivery_bucket_switch_date']) ? (string) $edit_store['delivery_bucket_switch_date'] : '';
    $delivery_bucket_after_value = $editing && isset($edit_store['delivery_bucket_after']) ? (string) $edit_store['delivery_bucket_after'] : '';
    $delivery_bucket_after_value = np_order_hub_normalize_delivery_bucket_optional($delivery_bucket_after_value);

    echo '<h2>' . esc_html($editing ? 'Edit Store' : 'Add Store') . '</h2>';
    if ($editing) {
        $cancel_url = admin_url('admin.php?page=np-order-hub-stores');
        echo '<p><a class="button" href="' . esc_url($cancel_url) . '">Cancel edit</a></p>';
    }
    echo '<form method="post">';
    wp_nonce_field($editing ? 'np_order_hub_update_store' : 'np_order_hub_add_store');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="store_key">Store Key</label></th>';
    echo '<td><input name="store_key" id="store_key" type="text" class="regular-text" value="' . esc_attr($store_key_value) . '"' . ($editing ? ' readonly' : '') . ' required />';
    echo $editing ? ' <p class="description">Store key cannot be changed.</p>' : ' <p class="description">Short ID like butikk1.</p>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="store_name">Store Name</label></th>';
    echo '<td><input name="store_name" id="store_name" type="text" class="regular-text" value="' . esc_attr($store_name_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_url">Store URL</label></th>';
    echo '<td><input name="store_url" id="store_url" type="url" class="regular-text" value="' . esc_attr($store_url_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_secret">Webhook Secret</label></th>';
    echo '<td><input name="store_secret" id="store_secret" type="text" class="regular-text" value="' . esc_attr($store_secret_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_token">Store Token</label></th>';
    echo '<td><input name="store_token" id="store_token" type="text" class="regular-text" value="' . esc_attr($store_token_value) . '" />';
    echo '<p class="description">Token from the store plugin (Order Hub Packing Slip page).</p></td></tr>';
    echo '<tr><th scope="row"><label for="store_consumer_key">WooCommerce API Key</label></th>';
    echo '<td><input name="store_consumer_key" id="store_consumer_key" type="text" class="regular-text" value="' . esc_attr($store_consumer_key_value) . '" />';
    echo '<p class="description">Consumer key with read permissions.</p></td></tr>';
    echo '<tr><th scope="row"><label for="store_consumer_secret">WooCommerce API Secret</label></th>';
    echo '<td><input name="store_consumer_secret" id="store_consumer_secret" type="text" class="regular-text" value="' . esc_attr($store_consumer_secret_value) . '" />';
    echo '<p class="description">Consumer secret for revenue import.</p></td></tr>';
    echo '<tr><th scope="row"><label for="order_url_type">Order URL Type</label></th>';
    echo '<td><select name="order_url_type" id="order_url_type">';
    echo '<option value="legacy"' . selected($order_url_type_value, 'legacy', false) . '>Legacy (post.php)</option>';
    echo '<option value="hpos"' . selected($order_url_type_value, 'hpos', false) . '>HPOS (wc-orders)</option>';
    echo '</select></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket">Default Delivery</label></th>';
    echo '<td><select name="delivery_bucket" id="delivery_bucket">';
    echo '<option value="standard"' . selected($delivery_bucket_value, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket_value, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p class="description">Used to place new orders in the correct dashboard automatically.</p></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket_switch_date">Bytt dato</label></th>';
    echo '<td><input name="delivery_bucket_switch_date" id="delivery_bucket_switch_date" type="date" class="regular-text" value="' . esc_attr($delivery_bucket_switch_date_value) . '" />';
    echo '<p class="description">Når denne datoen er passert, brukes "Bytt til" for nye ordre.</p></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket_after">Bytt til</label></th>';
    echo '<td><select name="delivery_bucket_after" id="delivery_bucket_after">';
    echo '<option value=""' . selected($delivery_bucket_after_value, '', false) . '>Ingen endring</option>';
    echo '<option value="standard"' . selected($delivery_bucket_after_value, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket_after_value, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p class="description">Valgfritt. Hvis tomt, bytter vi til motsatt av default.</p></td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="' . esc_attr($editing ? 'np_order_hub_update_store' : 'np_order_hub_add_store') . '" value="1">' . esc_html($editing ? 'Update Store' : 'Save Store') . '</button></p>';
    echo '</form>';

    echo '</div>';
}

if (is_admin()) {
    if (!class_exists('WP_List_Table')) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
    }

    class NP_Order_Hub_Orders_Table extends WP_List_Table {
    public function get_columns() {
        return array(
            'store' => 'Store',
            'order' => 'Order',
            'customer' => 'Customer',
            'date' => 'Date',
            'status' => 'Status',
            'reklamasjon' => 'Reklamasjon',
            'total' => 'Total',
            'actions' => '',
        );
    }

    protected function get_sortable_columns() {
        return array(
            'store' => array('store_name', false),
            'date' => array('date_created_gmt', true),
            'status' => array('status', false),
            'total' => array('total', false),
        );
    }

    public function column_store($item) {
        $name = isset($item['store_name']) ? $item['store_name'] : '';
        $url = isset($item['store_url']) ? $item['store_url'] : '';
        if ($url !== '') {
            return '<strong>' . esc_html($name) . '</strong><br /><span class="description">' . esc_html($url) . '</span>';
        }
        return esc_html($name);
    }

    public function column_order($item) {
        $number = isset($item['order_number']) ? $item['order_number'] : '';
        $order_id = isset($item['order_id']) ? (int) $item['order_id'] : 0;
        $label = $number !== '' ? ('#' . $number) : ('#' . $order_id);
        $url = isset($item['order_admin_url']) ? $item['order_admin_url'] : '';
        if ($url !== '') {
            return '<a href="' . esc_url($url) . '" target="_blank" rel="noopener">' . esc_html($label) . '</a>';
        }
        return esc_html($label);
    }

    public function column_customer($item) {
        return esc_html(np_order_hub_get_customer_label($item));
    }

    public function column_date($item) {
        $gmt = isset($item['date_created_gmt']) ? $item['date_created_gmt'] : '';
        if ($gmt === '' || $gmt === '0000-00-00 00:00:00') {
            return '';
        }
        $local = get_date_from_gmt($gmt, 'd.m.y');
        return esc_html($local);
    }

    public function column_status($item) {
        $status = isset($item['status']) ? $item['status'] : '';
        if ($status === '') {
            return '';
        }
        $label = ucwords(str_replace('-', ' ', $status));
        return esc_html($label);
    }

    public function column_reklamasjon($item) {
        return np_order_hub_record_is_reklamasjon($item) ? 'Ja' : '—';
    }

    public function column_total($item) {
        $total = isset($item['total']) ? (float) $item['total'] : 0.0;
        $currency = isset($item['currency']) ? $item['currency'] : '';
        $formatted = number_format_i18n($total, 2);
        $display = trim($formatted . ' ' . $currency);
        return esc_html($display);
    }

    public function column_actions($item) {
        $actions = array();
        $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $item['id']);
        $actions[] = '<a class="button button-small" href="' . esc_url($details_url) . '">Details</a>';

        $store = np_order_hub_get_store_by_key(isset($item['store_key']) ? $item['store_key'] : '');
        $packing_url = np_order_hub_build_packing_slip_url(
            $store,
            isset($item['order_id']) ? (int) $item['order_id'] : 0,
            isset($item['order_number']) ? (string) $item['order_number'] : '',
            isset($item['payload']) ? $item['payload'] : null
        );
        if ($packing_url !== '') {
            $actions[] = '<a class="button button-small" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
        }

        $url = isset($item['order_admin_url']) ? $item['order_admin_url'] : '';
        if ($url !== '') {
            $actions[] = '<a class="button button-small" href="' . esc_url($url) . '" target="_blank" rel="noopener">Open order</a>';
        }
        return implode(' ', $actions);
    }

    public function prepare_items() {
        global $wpdb;
        $table = np_order_hub_table_name();

        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();
        $this->_column_headers = array($columns, $hidden, $sortable);

        $orderby = isset($_GET['orderby']) ? sanitize_key((string) $_GET['orderby']) : 'date_created_gmt';
        $order = isset($_GET['order']) ? strtoupper((string) $_GET['order']) : 'DESC';

        $allowed_orderby = array('store_name', 'date_created_gmt', 'status', 'total');
        if (!in_array($orderby, $allowed_orderby, true)) {
            $orderby = 'date_created_gmt';
        }
        $order = $order === 'ASC' ? 'ASC' : 'DESC';

        $per_page = NP_ORDER_HUB_PER_PAGE;
        $current_page = $this->get_pagenum();
        $offset = ($current_page - 1) * $per_page;

        $total_items = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table");

        $items = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table ORDER BY $orderby $order LIMIT %d OFFSET %d",
                $per_page,
                $offset
            ),
            ARRAY_A
        );

        $this->items = $items;

        $this->set_pagination_args(array(
            'total_items' => $total_items,
            'per_page' => $per_page,
            'total_pages' => $per_page > 0 ? ceil($total_items / $per_page) : 1,
        ));
    }
    }
}
