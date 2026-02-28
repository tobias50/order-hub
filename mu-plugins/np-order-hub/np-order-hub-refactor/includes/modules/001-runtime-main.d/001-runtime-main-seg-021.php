<?php
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
    $normalized_status = sanitize_key((string) $status);
    if ($normalized_status !== 'processing') {
        return;
    }
    $store_name = is_array($store) && !empty($store['name']) ? (string) $store['name'] : 'Store';
    $total_display = np_order_hub_format_money((float) $total, (string) $currency);
    $message = $store_name . "\n" . $total_display;
    $title = 'Ny ordre';
    np_order_hub_send_pushover_message($title, $message);
}

function np_order_hub_get_allowed_statuses() {
    return array(
        'pending' => 'Pending',
        'processing' => 'Processing',
        'restordre' => 'Restordre',
        'bytte-storrelse' => 'Bytte størrelse',
        'completed' => 'Completed',
        'on-hold' => 'On-hold',
        'cancelled' => 'Cancelled',
        'refunded' => 'Refunded',
        'reklamasjon' => 'Reklamasjon',
        'failed' => 'Failed',
    );
}

function np_order_hub_push_shipping_config_to_store($store) {
    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_token', 'Store token missing.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'shipping-config');
    if ($endpoint === '') {
        return new WP_Error('missing_endpoint', 'Store endpoint missing.');
    }

    $shipping_window = np_order_hub_get_store_shipping_window($store);
    $response = wp_remote_post($endpoint, array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ),
        'body' => wp_json_encode(array(
            'token' => $token,
            'shipping_window' => array(
                'enabled' => !empty($shipping_window['shipping_window_enabled']),
                'start_date' => (string) ($shipping_window['shipping_window_start_date'] ?? ''),
                'end_date' => (string) ($shipping_window['shipping_window_end_date'] ?? ''),
                'method_keys' => isset($shipping_window['shipping_window_method_keys']) && is_array($shipping_window['shipping_window_method_keys'])
                    ? array_values($shipping_window['shipping_window_method_keys'])
                    : array(),
                'include_postnord_parcel_locker' => !empty($shipping_window['shipping_window_include_postnord_parcel_locker']),
            ),
        )),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        $message = 'Shipping config sync failed.';
        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (is_array($decoded) && !empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            }
        }
        return new WP_Error('shipping_config_sync_failed', $message, array(
            'status' => $code,
            'body' => $body,
        ));
    }

    $decoded = $body !== '' ? json_decode($body, true) : null;
    return is_array($decoded) ? $decoded : true;
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
