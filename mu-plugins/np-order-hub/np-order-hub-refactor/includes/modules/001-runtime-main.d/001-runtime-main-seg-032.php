<?php
function np_order_hub_get_supported_order_email_actions() {
    return array(
        'customer_processing_order' => 'Processing order',
        'customer_completed_order' => 'Completed order',
        'customer_invoice' => 'Order details / invoice',
    );
}

function np_order_hub_request_remote_order_endpoint($store, $endpoint, $method = 'GET', $data = array()) {
    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_token', 'Store token missing.');
    }

    $url = np_order_hub_build_store_api_url($store, $endpoint);
    if ($url === '') {
        return new WP_Error('missing_endpoint', 'Store endpoint missing.');
    }

    $method = strtoupper((string) $method);
    $args = array(
        'timeout' => 20,
        'method' => $method,
        'headers' => array(
            'Accept' => 'application/json',
        ),
    );

    if ($method === 'GET') {
        $query = is_array($data) ? $data : array();
        $query['token'] = $token;
        $url = add_query_arg($query, $url);
    } else {
        $payload = is_array($data) ? $data : array();
        $payload['token'] = $token;
        $args['headers']['Content-Type'] = 'application/json';
        $args['body'] = wp_json_encode($payload);
    }

    $response = wp_remote_request($url, $args);
    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;

    if ($code < 200 || $code >= 300) {
        $message = 'Remote order request failed.';
        if (is_array($decoded)) {
            if (!empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            } elseif (!empty($decoded['message'])) {
                $message = (string) $decoded['message'];
            }
        } elseif (is_string($body) && trim($body) !== '') {
            $message = trim($body);
        }
        return new WP_Error('remote_order_request_failed', $message, array(
            'status' => $code,
            'body' => $body,
            'endpoint' => $endpoint,
        ));
    }

    return is_array($decoded) ? $decoded : true;
}

function np_order_hub_fetch_remote_order_live($store, $order_id) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-live', 'GET', array(
        'order_id' => $order_id,
    ));
}

function np_order_hub_update_remote_order_addresses($store, $order_id, $billing, $shipping) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-addresses', 'POST', array(
        'order_id' => $order_id,
        'billing' => is_array($billing) ? $billing : array(),
        'shipping' => is_array($shipping) ? $shipping : array(),
    ));
}

function np_order_hub_add_remote_order_note($store, $order_id, $note) {
    $order_id = absint($order_id);
    $note = trim((string) $note);
    if ($order_id < 1 || $note === '') {
        return new WP_Error('missing_params', 'Missing order ID or note.');
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-note', 'POST', array(
        'order_id' => $order_id,
        'note' => $note,
    ));
}

function np_order_hub_update_remote_customer_note($store, $order_id, $customer_note) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-customer-note', 'POST', array(
        'order_id' => $order_id,
        'customer_note' => (string) $customer_note,
    ));
}

function np_order_hub_send_remote_order_email($store, $order_id, $email_action) {
    $order_id = absint($order_id);
    $email_action = sanitize_key((string) $email_action);
    if ($order_id < 1 || $email_action === '') {
        return new WP_Error('missing_params', 'Missing order ID or email action.');
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-email', 'POST', array(
        'order_id' => $order_id,
        'email_action' => $email_action,
    ));
}

function np_order_hub_get_record_payload_data($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return array();
    }
    $payload = json_decode((string) $record['payload'], true);
    return is_array($payload) ? $payload : array();
}

function np_order_hub_upsert_record_from_remote_payload($record, $store, $data) {
    if (!is_array($store) || !is_array($data)) {
        return is_array($record) ? $record : null;
    }

    $order_id = isset($data['id']) ? absint($data['id']) : 0;
    if ($order_id < 1 && is_array($record)) {
        $order_id = isset($record['order_id']) ? absint($record['order_id']) : 0;
    }
    if ($order_id < 1) {
        return is_array($record) ? $record : null;
    }

    global $wpdb;
    $table = np_order_hub_table_name();

    $existing = null;
    if (is_array($record) && !empty($record['id'])) {
        $existing = np_order_hub_get_record((int) $record['id']);
    }
    if (!$existing) {
        $existing = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM $table WHERE store_key = %s AND order_id = %d",
                (string) $store['key'],
                $order_id
            ),
            ARRAY_A
        );
    }

    $existing_payload = np_order_hub_get_record_payload_data($existing);
    $existing_bucket = np_order_hub_extract_delivery_bucket_from_payload_data($existing_payload);
    $store_bucket = np_order_hub_get_active_store_delivery_bucket($store);
    $data[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $existing_bucket !== '' ? $existing_bucket : $store_bucket;

    if (!empty($existing_payload['np_reklamasjon']) && empty($data['np_reklamasjon'])) {
        $data['np_reklamasjon'] = true;
    }
    if (!empty($existing_payload['np_reklamasjon_source_order']) && empty($data['np_reklamasjon_source_order'])) {
        $data['np_reklamasjon_source_order'] = (int) $existing_payload['np_reklamasjon_source_order'];
    }
    if (!empty($existing_payload['np_bytte_storrelse']) && empty($data['np_bytte_storrelse'])) {
        $data['np_bytte_storrelse'] = true;
    }
    if (!empty($existing_payload['np_bytte_storrelse_source_order']) && empty($data['np_bytte_storrelse_source_order'])) {
        $data['np_bytte_storrelse_source_order'] = (int) $existing_payload['np_bytte_storrelse_source_order'];
    }

    $order_number = isset($data['number']) ? sanitize_text_field((string) $data['number']) : (string) $order_id;
    $status = isset($data['status']) ? sanitize_key((string) $data['status']) : (is_array($record) ? sanitize_key((string) ($record['status'] ?? '')) : '');
    $currency = isset($data['currency']) ? sanitize_text_field((string) $data['currency']) : (is_array($record) ? sanitize_text_field((string) ($record['currency'] ?? '')) : '');
    $total_raw = isset($data['total']) ? (string) $data['total'] : '0';
    $total = is_numeric($total_raw) ? (float) $total_raw : 0.0;
    $date_created_gmt = np_order_hub_parse_datetime_gmt(
        $data['date_created_gmt'] ?? '',
        $data['date_created'] ?? ''
    );
    $date_modified_gmt = np_order_hub_parse_datetime_gmt(
        $data['date_modified_gmt'] ?? '',
        $data['date_modified'] ?? ''
    );

    $row = array(
        'store_key' => (string) $store['key'],
        'store_name' => (string) ($store['name'] ?? ''),
        'store_url' => (string) ($store['url'] ?? ''),
        'order_id' => $order_id,
        'order_number' => $order_number,
        'status' => $status,
        'currency' => $currency,
        'total' => $total,
        'date_created_gmt' => $date_created_gmt !== '' ? $date_created_gmt : null,
        'date_modified_gmt' => $date_modified_gmt !== '' ? $date_modified_gmt : null,
        'order_admin_url' => np_order_hub_build_admin_order_url($store, $order_id),
        'payload' => wp_json_encode($data),
        'updated_at_gmt' => current_time('mysql', true),
    );

    if ($existing && !empty($existing['id'])) {
        $wpdb->update($table, $row, array('id' => (int) $existing['id']));
        return np_order_hub_get_record((int) $existing['id']);
    }

    $row['created_at_gmt'] = current_time('mysql', true);
    $wpdb->insert($table, $row);
    return np_order_hub_get_record((int) $wpdb->insert_id);
}
