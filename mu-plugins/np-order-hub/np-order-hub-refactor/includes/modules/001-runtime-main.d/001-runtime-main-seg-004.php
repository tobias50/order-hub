<?php
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

function np_order_hub_build_admin_orders_url($store) {
    if (!is_array($store) || empty($store['url'])) {
        return '';
    }
    $admin_base = np_order_hub_build_admin_base_url($store['url']);
    if ($admin_base === '') {
        return '';
    }
    $type = isset($store['order_url_type']) ? $store['order_url_type'] : NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE;
    $type = $type === 'hpos' ? 'hpos' : 'legacy';
    if ($type === 'hpos') {
        return $admin_base . 'admin.php?page=wc-orders';
    }
    return $admin_base . 'edit.php?post_type=shop_order';
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

function np_order_hub_build_shipping_label_url($store, $order_id) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return '';
    }
    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return '';
    }
    $endpoint = np_order_hub_build_store_api_url($store, 'shipping-label');
    if ($endpoint === '') {
        return '';
    }
    return add_query_arg(array(
        'order_id' => $order_id,
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