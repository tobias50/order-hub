<?php
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
    if (!in_array($period, array('daily', 'weekly', 'month_current', 'month_previous', 'yearly', 'custom'), true)) {
        $period = 'daily';
    }

    $now = current_time('timestamp');
    $today = wp_date('Y-m-d', $now);

    if ($period === 'weekly') {
        $weekday = (int) wp_date('N', $now); // 1 (Mon) .. 7 (Sun)
        $start_ts = strtotime('-' . ($weekday - 1) . ' days', $now);
        $end_ts = strtotime('+' . (7 - $weekday) . ' days', $now);
        $from = wp_date('Y-m-d', $start_ts);
        $to = wp_date('Y-m-d', $end_ts);
    } elseif ($period === 'month_current') {
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