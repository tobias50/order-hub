<?php
function np_order_hub_log_signature_failure($store, $body, $signature, $request) {
    $store_key = is_array($store) && !empty($store['key']) ? (string) $store['key'] : '';
    $source = '';
    $user_agent = '';
    if ($request instanceof WP_REST_Request) {
        $source = (string) $request->get_header('X-WC-Webhook-Source');
        $user_agent = (string) $request->get_header('User-Agent');
    }

    $expected = array();
    foreach (array('secret', 'token') as $field) {
        $candidate = is_array($store) && isset($store[$field]) ? trim((string) $store[$field]) : '';
        if ($candidate === '') {
            continue;
        }
        $expected_signature = base64_encode(hash_hmac('sha256', $body, $candidate, true));
        $expected[$field] = array(
            'len' => strlen($candidate),
            'sig_hash' => substr(hash('sha256', $expected_signature), 0, 12),
        );
    }

    $context = array(
        'store_key' => $store_key,
        'source' => $source,
        'user_agent' => $user_agent,
        'signature_present' => $signature !== '',
        'signature_len' => strlen($signature),
        'signature_hash' => $signature !== '' ? substr(hash('sha256', $signature), 0, 12) : '',
        'body_len' => strlen($body),
        'body_hash' => $body !== '' ? substr(hash('sha256', $body), 0, 12) : '',
        'expected' => $expected,
    );

    error_log('[np-order-hub] webhook_bad_signature ' . wp_json_encode($context));
}

function np_order_hub_get_request_remote_ip() {
    $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
    if ($remote !== '') {
        return $remote;
    }

    $forwarded = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? (string) $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
    if ($forwarded === '') {
        return '';
    }

    $parts = explode(',', $forwarded);
    $candidate = isset($parts[0]) ? trim((string) $parts[0]) : '';
    return $candidate;
}

function np_order_hub_get_store_normalized_url($store) {
    if (!is_array($store)) {
        return '';
    }
    if (!empty($store['normalized_url'])) {
        return (string) $store['normalized_url'];
    }
    return np_order_hub_normalize_store_url(isset($store['url']) ? (string) $store['url'] : '');
}

function np_order_hub_get_store_host($store) {
    if (!is_array($store)) {
        return '';
    }

    $url = isset($store['url']) ? trim((string) $store['url']) : '';
    if ($url !== '') {
        $parsed = wp_parse_url($url);
        if (!empty($parsed['host'])) {
            return strtolower((string) $parsed['host']);
        }
    }

    $normalized = np_order_hub_get_store_normalized_url($store);
    if ($normalized === '') {
        return '';
    }

    $slash = strpos($normalized, '/');
    if ($slash !== false) {
        return strtolower(substr($normalized, 0, $slash));
    }

    return strtolower($normalized);
}

function np_order_hub_get_store_host_ips($store) {
    $host = np_order_hub_get_store_host($store);
    if ($host === '') {
        return array();
    }

    $ips = gethostbynamel($host);
    if (!is_array($ips) || empty($ips)) {
        return array();
    }

    $clean = array();
    foreach ($ips as $ip) {
        $ip = trim((string) $ip);
        if ($ip !== '') {
            $clean[$ip] = true;
        }
    }
    return array_keys($clean);
}

function np_order_hub_request_matches_store_ip($store, $request) {
    if (!($request instanceof WP_REST_Request)) {
        return false;
    }

    $remote_ip = np_order_hub_get_request_remote_ip();
    if ($remote_ip === '') {
        return false;
    }

    $host_ips = np_order_hub_get_store_host_ips($store);
    if (empty($host_ips)) {
        return false;
    }

    return in_array($remote_ip, $host_ips, true);
}

function np_order_hub_is_trusted_webhook_source_request($store, $request) {
    if (!($request instanceof WP_REST_Request) || !is_array($store)) {
        return false;
    }

    $source = (string) $request->get_header('X-WC-Webhook-Source');
    $user_agent = (string) $request->get_header('User-Agent');
    if ($source === '' || stripos($user_agent, 'WooCommerce/') === false) {
        return false;
    }

    $normalized_store = np_order_hub_get_store_normalized_url($store);
    $normalized_source = np_order_hub_normalize_store_url($source);
    if ($normalized_store === '' || $normalized_source === '' || $normalized_store !== $normalized_source) {
        return false;
    }

    return np_order_hub_request_matches_store_ip($store, $request);
}

function np_order_hub_is_trusted_webhook_ip_request($store, $request) {
    if (!($request instanceof WP_REST_Request) || !is_array($store)) {
        return false;
    }
    if (!np_order_hub_is_woocommerce_hookshot_request($request)) {
        return false;
    }
    return np_order_hub_request_matches_store_ip($store, $request);
}

function np_order_hub_is_woocommerce_hookshot_request($request) {
    if (!($request instanceof WP_REST_Request)) {
        return false;
    }
    $user_agent = strtolower((string) $request->get_header('User-Agent'));
    if ($user_agent === '') {
        return false;
    }
    return strpos($user_agent, 'woocommerce/') !== false && strpos($user_agent, 'hookshot') !== false;
}

function np_order_hub_is_ping_payload($body, $data, $event, $topic) {
    if ($event === 'ping' || $topic === 'webhook.ping') {
        return true;
    }

    if (is_array($data)) {
        if (!empty($data['webhook_id']) || !empty($data['ping'])) {
            return true;
        }
        if (!empty($data['action']) && strtolower((string) $data['action']) === 'ping') {
            return true;
        }
        if (!empty($data['resource']) && strtolower((string) $data['resource']) === 'ping') {
            return true;
        }
    }

    $trimmed = trim((string) $body);
    if ($trimmed === '') {
        return true;
    }

    if (strlen($trimmed) <= 80) {
        $lower = strtolower($trimmed);
        if (in_array($lower, array('ping', '{"ping":true}', '{"ping":"true"}', '{"ping":1}', '{}'), true)) {
            return true;
        }

        $params = array();
        parse_str($trimmed, $params);
        if (!empty($params['webhook_id']) || !empty($params['ping'])) {
            return true;
        }
        if (!empty($params['action']) && strtolower((string) $params['action']) === 'ping') {
            return true;
        }
    }

    return false;
}

function np_order_hub_log_hookshot_probe($store_key_param, $store, $request, $signature, $event, $topic, $data, $body) {
    if (!np_order_hub_is_woocommerce_hookshot_request($request)) {
        return;
    }

    $source = (string) $request->get_header('X-WC-Webhook-Source');
    $remote_ip = np_order_hub_get_request_remote_ip();
    $store_key = is_array($store) && !empty($store['key']) ? (string) $store['key'] : '';
    $host_ips = np_order_hub_get_store_host_ips($store);
    $context = array(
        'store_param' => sanitize_key((string) $store_key_param),
        'store_resolved' => $store_key,
        'source' => $source,
        'remote_ip' => $remote_ip,
        'store_ips' => $host_ips,
        'trusted_source_ip' => np_order_hub_is_trusted_webhook_source_request($store, $request),
        'trusted_hookshot_ip' => np_order_hub_is_trusted_webhook_ip_request($store, $request),
        'signature_present' => $signature !== '',
        'signature_len' => strlen((string) $signature),
        'event_header' => (string) $event,
        'topic_header' => (string) $topic,
        'body_len' => strlen((string) $body),
        'body_hash' => $body !== '' ? substr(hash('sha256', (string) $body), 0, 12) : '',
        'payload_json' => is_array($data),
    );

    if (is_array($data)) {
        $context['payload_id'] = isset($data['id']) ? absint($data['id']) : 0;
        $context['payload_number'] = isset($data['number']) ? (string) $data['number'] : '';
        $context['payload_status'] = isset($data['status']) ? sanitize_key((string) $data['status']) : '';
        $context['payload_webhook_id'] = isset($data['webhook_id']) ? absint($data['webhook_id']) : 0;
    }

    error_log('[np-order-hub] webhook_probe ' . wp_json_encode($context));
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