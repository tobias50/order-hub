<?php
function np_order_hub_wpo_build_order_payload_for_hub($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return array();
    }

    $payload = np_order_hub_wpo_get_rest_order_payload($order);
    if (!is_array($payload) || empty($payload['id'])) {
        $payload = np_order_hub_wpo_get_fallback_order_payload($order);
    }
    if (!is_array($payload)) {
        $payload = array();
    }

    if (function_exists('np_order_hub_add_wpo_access_key')) {
        $payload = np_order_hub_add_wpo_access_key($payload, 'order', (int) $order->get_id(), 0);
    }

    $payload['id'] = (int) $order->get_id();
    if (empty($payload['number'])) {
        $payload['number'] = (string) $order->get_order_number();
    }
    if (empty($payload['status'])) {
        $payload['status'] = (string) $order->get_status();
    }
    if (empty($payload['currency'])) {
        $payload['currency'] = (string) $order->get_currency();
    }
    if (!isset($payload['total']) || $payload['total'] === '') {
        $payload['total'] = wc_format_decimal((float) $order->get_total(), wc_get_price_decimals());
    }

    return $payload;
}

function np_order_hub_wpo_make_webhook_signature($body, $secret) {
    $secret = (string) $secret;
    if ($secret === '') {
        return '';
    }
    return base64_encode(hash_hmac('sha256', (string) $body, $secret, true));
}

function np_order_hub_wpo_topic_matches_event($topic, $event) {
    $topic = strtolower(trim((string) $topic));
    $event = sanitize_key((string) $event);
    if ($topic === '' || $event === '') {
        return true;
    }
    if (strpos($topic, 'action.') === 0) {
        return true;
    }
    if (strpos($topic, 'order.') !== 0) {
        return false;
    }
    $topic_event = substr($topic, 6);
    if ($topic_event === '') {
        return true;
    }
    return $topic_event === $event;
}

function np_order_hub_wpo_dispatch_payload_to_hub_targets($targets, $payload, $event = 'created') {
    if (empty($targets) || !is_array($targets) || !is_array($payload)) {
        return;
    }

    $event = strtolower((string) $event);
    if (!in_array($event, array('created', 'updated', 'deleted'), true)) {
        $event = 'created';
    }

    $body = wp_json_encode($payload);
    if (!is_string($body) || $body === '') {
        np_order_hub_wpo_log('direct_push_encode_failed', array(
            'event' => $event,
            'order_id' => isset($payload['id']) ? (int) $payload['id'] : 0,
        ));
        return;
    }

    $source = trailingslashit(home_url('/'));
    $wc_version = defined('WC_VERSION') ? (string) WC_VERSION : 'unknown';
    $wp_version = get_bloginfo('version');
    $user_agent = 'WooCommerce/' . $wc_version . ' Hookshot (WordPress/' . $wp_version . '; NP-DirectPush)';

    $prepared_targets = array();
    $matching_targets = array();
    foreach ($targets as $target) {
        if (!is_array($target) || empty($target['delivery_url'])) {
            continue;
        }
        $target['topic'] = !empty($target['topic']) ? (string) $target['topic'] : 'order.created';
        $prepared_targets[] = $target;
        if (np_order_hub_wpo_topic_matches_event($target['topic'], $event)) {
            $matching_targets[] = $target;
        }
    }

    $dispatch_targets = !empty($matching_targets) ? $matching_targets : $prepared_targets;
    if (empty($dispatch_targets)) {
        return;
    }

    $unique_targets = array();
    $deduped_targets = array();
    foreach ($dispatch_targets as $target) {
        $delivery_url = !empty($target['delivery_url']) ? strtolower(trim((string) $target['delivery_url'])) : '';
        if ($delivery_url === '') {
            continue;
        }
        $secret_hash = md5((string) (isset($target['secret']) ? $target['secret'] : ''));
        $target_key = $delivery_url . '|' . $secret_hash;
        if (isset($unique_targets[$target_key])) {
            continue;
        }
        $unique_targets[$target_key] = true;
        $deduped_targets[] = $target;
    }
    $dispatch_targets = $deduped_targets;
    if (empty($dispatch_targets)) {
        return;
    }

    if (empty($matching_targets)) {
        np_order_hub_wpo_log('direct_push_topic_fallback', array(
            'event' => $event,
            'order_id' => isset($payload['id']) ? (int) $payload['id'] : 0,
            'target_count' => count($dispatch_targets),
        ));
    }

    foreach ($dispatch_targets as $target) {
        $delivery_url = (string) $target['delivery_url'];
        $topic = (string) $target['topic'];
        $topic_for_header = np_order_hub_wpo_topic_matches_event($topic, $event) ? $topic : ('order.' . $event);
        $webhook_id = isset($target['id']) ? (int) $target['id'] : 0;
        $signature = np_order_hub_wpo_make_webhook_signature($body, isset($target['secret']) ? $target['secret'] : '');

        $headers = array(
            'Content-Type' => 'application/json',
            'User-Agent' => $user_agent,
            'X-WC-Webhook-Source' => $source,
            'X-WC-Webhook-Topic' => $topic_for_header,
            'X-WC-Webhook-Resource' => 'order',
            'X-WC-Webhook-Event' => $event,
            'X-WC-Webhook-Delivery-ID' => wp_generate_uuid4(),
        );
        if ($webhook_id > 0) {
            $headers['X-WC-Webhook-ID'] = (string) $webhook_id;
        }
        if ($signature !== '') {
            $headers['X-WC-Webhook-Signature'] = $signature;
        }

        $response = wp_remote_post($delivery_url, array(
            'timeout' => 20,
            'redirection' => 3,
            'headers' => $headers,
            'body' => $body,
        ));

        $log_context = array(
            'event' => $event,
            'order_id' => isset($payload['id']) ? (int) $payload['id'] : 0,
            'webhook_id' => $webhook_id,
            'delivery_url' => $delivery_url,
        );

        if (is_wp_error($response)) {
            $log_context['result'] = 'wp_error';
            $log_context['error'] = $response->get_error_message();
            np_order_hub_wpo_log('direct_push_failed', $log_context);
            continue;
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $log_context['status'] = $code;
        if ($code >= 200 && $code < 300) {
            np_order_hub_wpo_log('direct_push_ok', $log_context);
            continue;
        }

        $body_text = wp_remote_retrieve_body($response);
        $log_context['body'] = is_string($body_text) ? substr(wp_strip_all_tags($body_text), 0, 300) : '';
        np_order_hub_wpo_log('direct_push_failed', $log_context);
    }
}

function np_order_hub_wpo_is_duplicate_request_push($order_id, $event, $order = null) {
    static $seen = array();

    $order_id = absint($order_id);
    $event = sanitize_key((string) $event);
    if ($order_id < 1 || $event === '') {
        return false;
    }

    $status = '';
    $modified_ts = '';
    $total = '';
    if ($event !== 'deleted' && $order && is_a($order, 'WC_Order')) {
        $status = method_exists($order, 'get_status') ? (string) $order->get_status() : '';
        $modified = method_exists($order, 'get_date_modified') ? $order->get_date_modified() : null;
        if ($modified && is_a($modified, 'WC_DateTime')) {
            $modified_ts = (string) $modified->getTimestamp();
        }
        if (method_exists($order, 'get_total')) {
            $total = wc_format_decimal((float) $order->get_total(), wc_get_price_decimals());
        }
    }

    $fingerprint = implode('|', array(
        (string) $order_id,
        $event,
        $status,
        $modified_ts,
        $total,
    ));
    if (isset($seen[$fingerprint])) {
        return true;
    }
    $seen[$fingerprint] = true;
    return false;
}

function np_order_hub_wpo_push_order_to_hub($order_id, $event = 'created', $order = null) {
    $event = sanitize_key((string) $event);
    if (!in_array($event, array('created', 'updated', 'deleted'), true)) {
        $event = 'created';
    }
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return;
    }
    if (np_order_hub_wpo_is_hub_disabled()) {
        return;
    }
    if (!function_exists('wc_get_order')) {
        return;
    }
    if (!np_order_hub_wpo_acquire_direct_push_lock($order_id, $event)) {
        return;
    }

    try {
        $targets = np_order_hub_wpo_get_hub_webhook_targets();
        if (empty($targets)) {
            np_order_hub_wpo_log('direct_push_skipped_no_targets', array(
                'order_id' => $order_id,
                'event' => $event,
            ));
            return;
        }

        if (!$order || !is_a($order, 'WC_Order')) {
            $order = wc_get_order($order_id);
        }

        if ($order && is_a($order, 'WC_Order')) {
            $created_via = method_exists($order, 'get_created_via') ? (string) $order->get_created_via() : '';
            if ($created_via === 'np-order-hub') {
                return;
            }
        } elseif ($event !== 'deleted') {
            return;
        }

        if (np_order_hub_wpo_is_duplicate_request_push($order_id, $event, $order)) {
            return;
        }

        $payload = ($order && is_a($order, 'WC_Order'))
            ? np_order_hub_wpo_build_order_payload_for_hub($order)
            : array('id' => $order_id, 'number' => (string) $order_id);

        np_order_hub_wpo_dispatch_payload_to_hub_targets($targets, $payload, $event);
    } catch (Throwable $error) {
        np_order_hub_wpo_log('direct_push_exception', array(
            'order_id' => $order_id,
            'event' => $event,
            'error' => $error->getMessage(),
            'line' => (int) $error->getLine(),
        ));
    }

    np_order_hub_wpo_release_direct_push_lock($order_id, $event);
}