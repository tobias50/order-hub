<?php
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

function np_order_hub_get_vat_rate() {
    $rate = defined('NP_ORDER_HUB_VAT_RATE') ? (float) NP_ORDER_HUB_VAT_RATE : 0.25;
    if ($rate < 0) {
        $rate = 0.0;
    }
    return $rate;
}

function np_order_hub_format_vat_rate_label($vat_rate = null) {
    $rate = is_numeric($vat_rate) ? (float) $vat_rate : np_order_hub_get_vat_rate();
    $percent = $rate * 100;
    if (abs($percent - round($percent)) < 0.0001) {
        return (string) ((int) round($percent)) . '%';
    }
    $formatted = rtrim(rtrim(number_format($percent, 2, '.', ''), '0'), '.');
    return $formatted . '%';
}

function np_order_hub_split_amount_with_vat($gross_amount, $vat_rate = null) {
    $gross = (float) $gross_amount;
    $rate = is_numeric($vat_rate) ? (float) $vat_rate : np_order_hub_get_vat_rate();
    if ($rate <= 0) {
        return array(
            'gross' => $gross,
            'net' => $gross,
            'vat' => 0.0,
            'rate' => 0.0,
        );
    }

    $divider = 1 + $rate;
    if ($divider <= 0) {
        return array(
            'gross' => $gross,
            'net' => $gross,
            'vat' => 0.0,
            'rate' => $rate,
        );
    }

    $net = $gross / $divider;
    $vat = $gross - $net;
    return array(
        'gross' => $gross,
        'net' => $net,
        'vat' => $vat,
        'rate' => $rate,
    );
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
    $np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;
    $path = plugin_dir_path($np_order_hub_main_file) . 'assets/pushover-logo.svg';
    if (!file_exists($path)) {
        return '';
    }
    return plugins_url('assets/pushover-logo.svg', $np_order_hub_main_file);
}

function np_order_hub_pushover_resolve_logo_source($logo_url) {
    $logo_url = trim((string) $logo_url);
    if ($logo_url === '') {
        return array('file' => '', 'cleanup' => false);
    }

    if (preg_match('#^https?://#i', $logo_url)) {
        $np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;
        $plugin_url = plugins_url('/', $np_order_hub_main_file);
        if (strpos($logo_url, $plugin_url) === 0) {
            $relative = ltrim(substr($logo_url, strlen($plugin_url)), '/');
            $file_path = plugin_dir_path($np_order_hub_main_file) . str_replace('/', DIRECTORY_SEPARATOR, $relative);
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