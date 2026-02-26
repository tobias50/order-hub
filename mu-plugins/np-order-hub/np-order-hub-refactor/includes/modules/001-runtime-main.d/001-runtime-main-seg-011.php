<?php
function np_order_hub_is_delete_payload($event, $topic, $data) {
    $event = sanitize_key((string) $event);
    $topic = strtolower(trim((string) $topic));

    if (in_array($event, array('deleted', 'delete', 'trashed', 'trash', 'removed', 'remove'), true)) {
        return true;
    }

    if ($topic !== '' && preg_match('/(^|\\.)(deleted|delete|trashed|trash|removed|remove)$/', $topic)) {
        return true;
    }

    if (!is_array($data)) {
        return false;
    }

    if (array_key_exists('deleted', $data)) {
        $deleted = $data['deleted'];
        if ($deleted === true) {
            return true;
        }
        if (is_numeric($deleted) && (int) $deleted === 1) {
            return true;
        }
        if (is_string($deleted)) {
            $deleted = strtolower(trim($deleted));
            if (in_array($deleted, array('1', 'true', 'yes'), true)) {
                return true;
            }
        }
    }

    $status = isset($data['status']) ? sanitize_key((string) $data['status']) : '';
    if (strpos($status, 'wc-') === 0) {
        $status = substr($status, 3);
    }

    if (in_array($status, array('trash', 'trashed', 'deleted', 'auto-draft'), true)) {
        return true;
    }

    return false;
}

function np_order_hub_handle_webhook(WP_REST_Request $request) {
    $body = $request->get_body();
    $signature = (string) $request->get_header('X-WC-Webhook-Signature');
    $event = strtolower((string) $request->get_header('X-WC-Webhook-Event'));
    $topic = strtolower((string) $request->get_header('X-WC-Webhook-Topic'));
    $data = json_decode($body, true);
    if (!is_array($data)) {
        $data = null;
    }
    $is_ping_payload = np_order_hub_is_ping_payload($body, $data, $event, $topic);
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
    if (!$store && is_array($data)) {
        $store = np_order_hub_maybe_auto_register_store_from_request($store_key, $request, $data);
    }
    if (!$store) {
        return new WP_REST_Response(array('error' => 'unknown_store'), 401);
    }
    if (is_array($data)) {
        $store = np_order_hub_maybe_enrich_store_auth_from_payload($store, $data);
    }

    np_order_hub_log_hookshot_probe($store_key, $store, $request, $signature, $event, $topic, $data, $body);

    // WooCommerce webhook validation can send unsigned ping payloads during save/test.
    if ($signature === '' && $is_ping_payload && np_order_hub_is_woocommerce_hookshot_request($request)) {
        return new WP_REST_Response(array('status' => 'ping'), 200);
    }

    $trusted_source_ip = np_order_hub_is_trusted_webhook_source_request($store, $request);
    $trusted_hookshot_ip = np_order_hub_is_trusted_webhook_ip_request($store, $request);
    $has_store_secret = !empty(np_order_hub_get_store_webhook_secrets($store));
    if (!$has_store_secret) {
        if (!$trusted_source_ip && !$trusted_hookshot_ip) {
            return new WP_REST_Response(array('error' => 'missing_secret'), 401);
        }
        $reason = $trusted_source_ip ? 'source+ip matched store' : 'hookshot+ip matched store';
        error_log('[np-order-hub] webhook_missing_secret_bypass ' . $reason);
    } elseif (!np_order_hub_verify_store_signature($body, $signature, $store)) {
        if (!$trusted_source_ip && !$trusted_hookshot_ip) {
            np_order_hub_log_signature_failure($store, $body, $signature, $request);
            return new WP_REST_Response(array('error' => 'bad_signature'), 401);
        }
        $reason = $trusted_source_ip ? 'source+ip matched store' : 'hookshot+ip matched store';
        error_log('[np-order-hub] webhook_signature_bypass ' . $reason);
    }

    if (!is_array($data)) {
        return new WP_REST_Response(array('error' => 'bad_payload'), 400);
    }

    if (empty($data['id'])) {
        $webhook_id = isset($data['webhook_id']) ? absint($data['webhook_id']) : 0;
        if ($webhook_id > 0 || $event === 'ping' || $topic === 'webhook.ping') {
            return new WP_REST_Response(array('status' => 'ping'), 200);
        }
        return new WP_REST_Response(array('error' => 'bad_payload'), 400);
    }

    if ($event === '' && $topic !== '' && strpos($topic, '.') !== false) {
        $topic_parts = explode('.', $topic, 2);
        if (isset($topic_parts[1])) {
            $event = (string) $topic_parts[1];
        }
    }

    $order_id = absint($data['id']);
    if (np_order_hub_is_delete_payload($event, $topic, $data)) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $job_key = np_order_hub_print_queue_job_key(isset($store['key']) ? $store['key'] : '', $order_id);
        if ($job_key !== '') {
            np_order_hub_print_queue_remove_job($job_key);
        }
        $wpdb->delete($table, array(
            'store_key' => $store['key'],
            'order_id' => $order_id,
        ), array('%s', '%d'));
        return new WP_REST_Response(array('status' => 'deleted'), 200);
    }

    $data = np_order_hub_strip_store_credentials_from_payload($data);

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
    $existing_payload = array();
    if ($existing && !empty($existing['payload'])) {
        $decoded_existing_payload = json_decode((string) $existing['payload'], true);
        if (is_array($decoded_existing_payload)) {
            $existing_payload = $decoded_existing_payload;
        }
    }
    $store_bucket = np_order_hub_get_active_store_delivery_bucket($store);
    // Delivery bucket styres kun fra hubens butikk-innstillinger.
    // Eksisterende ordre beholder tidligere bucket, nye ordre får aktiv butikk-bucket.
    $bucket_to_set = $existing_bucket !== '' ? $existing_bucket : $store_bucket;
    $data[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $bucket_to_set;
    // Behold spesialtagger på eksisterende ordre selv om status senere endres til completed.
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
        $updated = $wpdb->update($table, $record, array('id' => $existing_id));
        if ($updated === false) {
            error_log('[np-order-hub] webhook_db_update_failed ' . wp_json_encode(array(
                'store_key' => $store['key'],
                'order_id' => $order_id,
                'db_error' => $wpdb->last_error,
            )));
            return new WP_REST_Response(array('error' => 'db_update_failed'), 500);
        }
    } else {
        $record['created_at_gmt'] = $now_gmt;
        $record['updated_at_gmt'] = $now_gmt;
        $inserted = $wpdb->insert($table, $record);
        if ($inserted === false) {
            error_log('[np-order-hub] webhook_db_insert_failed ' . wp_json_encode(array(
                'store_key' => $store['key'],
                'order_id' => $order_id,
                'db_error' => $wpdb->last_error,
            )));
            return new WP_REST_Response(array('error' => 'db_insert_failed'), 500);
        }
        np_order_hub_maybe_notify_new_order($store, $order_number, $order_id, $status, $total, $currency);
    }

    $record['id'] = $existing_id ? $existing_id : (int) $wpdb->insert_id;
    np_order_hub_print_queue_queue_order($store, $record, $existing_id ? 'updated' : 'created');

    return new WP_REST_Response(array('status' => 'ok'), 200);
}

add_action('admin_menu', 'np_order_hub_admin_menu');

function np_order_hub_admin_menu() {
    $capability = 'manage_options';
    $standard_processing_count = np_order_hub_get_processing_count_for_bucket('standard');
    $scheduled_processing_count = np_order_hub_get_processing_count_for_bucket(NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED);
    $standard_menu_title = 'Levering 3-5 dager';
    if ($standard_processing_count > 0) {
        $standard_menu_title .= ' <span class="awaiting-mod">' . (int) $standard_processing_count . '</span>';
    }
    $scheduled_menu_title = 'Levering til bestemt dato';
    if ($scheduled_processing_count > 0) {
        $scheduled_menu_title .= ' <span class="awaiting-mod">' . (int) $scheduled_processing_count . '</span>';
    }
    add_menu_page(
        'Order Hub',
        'Order Hub',
        $capability,
        'np-order-hub',
        'np_order_hub_orders_page',
        'dashicons-clipboard',
        56
    );
    add_submenu_page('np-order-hub', 'Levering 3-5 dager', $standard_menu_title, $capability, 'np-order-hub-dashboard', 'np_order_hub_dashboard_page');
    add_submenu_page('np-order-hub', 'Levering til bestemt dato', $scheduled_menu_title, $capability, 'np-order-hub-scheduled', 'np_order_hub_dashboard_page');
    add_submenu_page('np-order-hub', 'Omsetning', 'Omsetning', $capability, 'np-order-hub-revenue', 'np_order_hub_revenue_page');
    add_submenu_page('np-order-hub', 'Reklamasjon', 'Reklamasjon', $capability, 'np-order-hub-reklamasjon', 'np_order_hub_reklamasjon_page');
    add_submenu_page('np-order-hub', 'Restordre', 'Restordre', $capability, 'np-order-hub-restordre', 'np_order_hub_restordre_page');
    add_submenu_page('np-order-hub', 'Bytte størrelse', 'Bytte størrelse', $capability, 'np-order-hub-bytte-storrelse', 'np_order_hub_bytte_storrelse_page');
	    add_submenu_page('np-order-hub', 'Ødelagt plagg', 'Ødelagt plagg', $capability, 'np-order-hub-produksjonsfeil', 'np_order_hub_produksjonsfeil_page');
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
