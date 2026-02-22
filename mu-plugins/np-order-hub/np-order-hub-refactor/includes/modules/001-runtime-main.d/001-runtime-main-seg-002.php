<?php
function np_order_hub_normalize_shipping_method_key($key) {
    $key = strtolower(trim((string) $key));
    if ($key === '') {
        return '';
    }
    $key = preg_replace('/\s+/', '', $key);
    $key = preg_replace('/[^a-z0-9_:-]/', '', $key);
    return is_string($key) ? $key : '';
}

function np_order_hub_normalize_shipping_method_keys($keys) {
    if (!is_array($keys)) {
        $keys = preg_split('/[\r\n,;]+/', (string) $keys);
    }
    if (!is_array($keys)) {
        return array();
    }

    $normalized = array();
    foreach ($keys as $key) {
        $clean = np_order_hub_normalize_shipping_method_key($key);
        if ($clean !== '') {
            $normalized[$clean] = true;
        }
    }
    return array_keys($normalized);
}

function np_order_hub_shipping_method_keys_to_text($keys) {
    $keys = np_order_hub_normalize_shipping_method_keys($keys);
    return implode("\n", $keys);
}

function np_order_hub_sanitize_store_shipping_window($data, $existing = array()) {
    if (!is_array($data)) {
        $data = array();
    }
    if (!is_array($existing)) {
        $existing = array();
    }

    $window_payload = isset($data['shipping_window']) && is_array($data['shipping_window']) ? $data['shipping_window'] : array();

    $enabled_raw = $existing['shipping_window_enabled'] ?? 0;
    if (array_key_exists('shipping_window_enabled', $data)) {
        $enabled_raw = $data['shipping_window_enabled'];
    } elseif (array_key_exists('enabled', $window_payload)) {
        $enabled_raw = $window_payload['enabled'];
    }

    $start_raw = isset($existing['shipping_window_start_date']) ? (string) $existing['shipping_window_start_date'] : '';
    if (array_key_exists('shipping_window_start_date', $data)) {
        $start_raw = sanitize_text_field((string) $data['shipping_window_start_date']);
    } elseif (array_key_exists('start_date', $window_payload)) {
        $start_raw = sanitize_text_field((string) $window_payload['start_date']);
    }

    $end_raw = isset($existing['shipping_window_end_date']) ? (string) $existing['shipping_window_end_date'] : '';
    if (array_key_exists('shipping_window_end_date', $data)) {
        $end_raw = sanitize_text_field((string) $data['shipping_window_end_date']);
    } elseif (array_key_exists('end_date', $window_payload)) {
        $end_raw = sanitize_text_field((string) $window_payload['end_date']);
    }

    $keys_raw = array_key_exists('shipping_window_method_keys', $data)
        ? $data['shipping_window_method_keys']
        : (isset($existing['shipping_window_method_keys']) ? $existing['shipping_window_method_keys'] : array());
    if (array_key_exists('method_keys', $window_payload)) {
        $keys_raw = $window_payload['method_keys'];
    }

    $include_postnord_raw = $existing['shipping_window_include_postnord_parcel_locker'] ?? 0;
    if (array_key_exists('shipping_window_include_postnord_parcel_locker', $data)) {
        $include_postnord_raw = $data['shipping_window_include_postnord_parcel_locker'];
    } elseif (array_key_exists('include_postnord_parcel_locker', $window_payload)) {
        $include_postnord_raw = $window_payload['include_postnord_parcel_locker'];
    }

    $start = preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_raw) ? $start_raw : '';
    $end = preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_raw) ? $end_raw : '';
    if ($start !== '' && $end !== '' && strcmp($start, $end) > 0) {
        $tmp = $start;
        $start = $end;
        $end = $tmp;
    }

    $method_keys = np_order_hub_normalize_shipping_method_keys($keys_raw);
    $enabled = filter_var($enabled_raw, FILTER_VALIDATE_BOOLEAN);
    if (empty($method_keys)) {
        $enabled = false;
    }

    return array(
        'shipping_window_enabled' => $enabled ? 1 : 0,
        'shipping_window_start_date' => $start,
        'shipping_window_end_date' => $end,
        'shipping_window_method_keys' => $method_keys,
        'shipping_window_include_postnord_parcel_locker' => filter_var($include_postnord_raw, FILTER_VALIDATE_BOOLEAN) ? 1 : 0,
    );
}

function np_order_hub_get_store_shipping_window($store) {
    return np_order_hub_sanitize_store_shipping_window(is_array($store) ? $store : array(), is_array($store) ? $store : array());
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
    $existing = isset($stores[$key]) && is_array($stores[$key]) ? $stores[$key] : array();
    $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($data['delivery_bucket'] ?? ($existing['delivery_bucket'] ?? 'standard')));
    $switch_date_raw = sanitize_text_field((string) ($data['delivery_bucket_switch_date'] ?? ($existing['delivery_bucket_switch_date'] ?? '')));
    $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
    $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($data['delivery_bucket_after'] ?? ($existing['delivery_bucket_after'] ?? '')));
    $shipping_window = np_order_hub_sanitize_store_shipping_window($data, $existing);

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
        'shipping_window_enabled' => $shipping_window['shipping_window_enabled'],
        'shipping_window_start_date' => $shipping_window['shipping_window_start_date'],
        'shipping_window_end_date' => $shipping_window['shipping_window_end_date'],
        'shipping_window_method_keys' => $shipping_window['shipping_window_method_keys'],
        'shipping_window_include_postnord_parcel_locker' => $shipping_window['shipping_window_include_postnord_parcel_locker'],
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

    $shipping_sync = np_order_hub_push_shipping_config_to_store($upsert);
    $shipping_sync_response = array('ok' => true);
    if (is_wp_error($shipping_sync)) {
        $shipping_sync_response = array(
            'ok' => false,
            'error' => $shipping_sync->get_error_message(),
        );
    }

    return new WP_REST_Response(array(
        'ok' => true,
        'store' => $upsert,
        'shipping_sync' => $shipping_sync_response,
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

function np_order_hub_get_store_webhook_secrets($store) {
    if (!is_array($store)) {
        return array();
    }

    $secrets = array();
    foreach (array('secret', 'token') as $field) {
        $candidate = isset($store[$field]) ? trim((string) $store[$field]) : '';
        if ($candidate !== '') {
            $secrets[$candidate] = true;
        }
    }

    return array_keys($secrets);
}

function np_order_hub_verify_store_signature($body, $signature, $store) {
    $secrets = np_order_hub_get_store_webhook_secrets($store);
    foreach ($secrets as $secret) {
        if (np_order_hub_verify_signature($body, $signature, $secret)) {
            return true;
        }
    }
    return false;
}