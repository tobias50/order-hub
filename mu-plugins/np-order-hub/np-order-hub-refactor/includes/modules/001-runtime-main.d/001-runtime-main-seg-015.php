<?php
function np_order_hub_get_revenue_excluded_statuses() {
    return array('cancelled', 'refunded', 'reklamasjon', 'bytte-storrelse');
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