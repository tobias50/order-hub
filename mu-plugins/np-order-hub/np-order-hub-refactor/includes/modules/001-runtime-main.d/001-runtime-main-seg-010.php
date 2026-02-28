<?php
function np_order_hub_print_queue_claim_next_ready_job($agent_name = '') {
    np_order_hub_print_queue_release_stale_printing_jobs();

    $jobs = np_order_hub_print_queue_get_jobs();
    if (empty($jobs)) {
        return null;
    }

    $ready_keys = array();
    foreach ($jobs as $job_key => $job) {
        if (!is_array($job)) {
            continue;
        }
        if ((isset($job['status']) ? (string) $job['status'] : '') !== 'ready') {
            continue;
        }
        $updated_ts = isset($job['updated_at_gmt']) ? strtotime((string) $job['updated_at_gmt']) : 0;
        $ready_keys[] = array(
            'job_key' => (string) $job_key,
            'updated_ts' => $updated_ts > 0 ? $updated_ts : 0,
        );
    }

    if (empty($ready_keys)) {
        return null;
    }

    usort($ready_keys, function ($a, $b) {
        if ($a['updated_ts'] === $b['updated_ts']) {
            return strcmp((string) $a['job_key'], (string) $b['job_key']);
        }
        return $a['updated_ts'] < $b['updated_ts'] ? -1 : 1;
    });

    $selected_key = (string) $ready_keys[0]['job_key'];
    if (!isset($jobs[$selected_key]) || !is_array($jobs[$selected_key])) {
        return null;
    }

    $claim_id = wp_generate_password(32, false, false);
    $job = $jobs[$selected_key];
    $job['status'] = 'printing';
    $job['claim_id'] = $claim_id;
    $job['claim_by'] = sanitize_text_field((string) $agent_name);
    $job['claim_expires_gmt'] = gmdate('Y-m-d H:i:s', time() + NP_ORDER_HUB_PRINT_AGENT_CLAIM_TIMEOUT_SECONDS);
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    np_order_hub_print_queue_append_log($job, 'Claimed by print agent' . ($job['claim_by'] !== '' ? ' (' . $job['claim_by'] . ')' : '') . '.');
    $jobs[$selected_key] = $job;
    np_order_hub_print_queue_save_jobs($jobs);

    return np_order_hub_print_queue_build_agent_payload($selected_key, $job);
}

function np_order_hub_print_queue_finish_claimed_job($job_key, $claim_id, $success, $error_message = '') {
    $job_key = sanitize_text_field((string) $job_key);
    $claim_id = sanitize_text_field((string) $claim_id);
    if ($job_key === '' || $claim_id === '') {
        return new WP_Error('print_finish_missing_fields', 'Job key and claim ID are required.');
    }

    $jobs = np_order_hub_print_queue_get_jobs();
    if (!isset($jobs[$job_key]) || !is_array($jobs[$job_key])) {
        return new WP_Error('print_finish_not_found', 'Print job not found.');
    }
    $job = $jobs[$job_key];
    $stored_claim_id = isset($job['claim_id']) ? (string) $job['claim_id'] : '';
    if ($stored_claim_id === '' || !hash_equals($stored_claim_id, $claim_id)) {
        return new WP_Error('print_finish_claim_mismatch', 'Claim token mismatch.');
    }

    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    $job['claim_expires_gmt'] = '';

    if ($success) {
        $job['status'] = 'completed';
        $job['completed_at_gmt'] = gmdate('Y-m-d H:i:s');
        $job['print_error'] = '';
        $job['last_error'] = '';
        np_order_hub_print_queue_append_log($job, 'Printed successfully by agent.');
    } else {
        $job['print_attempts'] = isset($job['print_attempts']) ? ((int) $job['print_attempts'] + 1) : 1;
        $job['print_error'] = sanitize_text_field((string) $error_message);
        $job['last_error'] = $job['print_error'];
        if ((int) $job['print_attempts'] >= 5) {
            $job['status'] = 'failed_print';
            np_order_hub_print_queue_append_log($job, 'Print failed permanently: ' . $job['print_error']);
        } else {
            $job['status'] = 'ready';
            np_order_hub_print_queue_append_log($job, 'Print failed, returned to ready: ' . $job['print_error']);
        }
    }

    $job['claim_id'] = '';
    $job['claim_by'] = '';
    $jobs[$job_key] = $job;
    np_order_hub_print_queue_save_jobs($jobs);

    return np_order_hub_print_queue_build_agent_payload($job_key, $job);
}

function np_order_hub_print_queue_get_active_jobs($jobs) {
    $active = array();
    if (!is_array($jobs)) {
        return $active;
    }
    foreach ($jobs as $job_key => $job) {
        if (!is_array($job)) {
            continue;
        }
        $status = isset($job['status']) ? (string) $job['status'] : '';
        if (!in_array($status, array('pending', 'retry', 'running', 'ready', 'printing'), true)) {
            continue;
        }
        $updated = isset($job['updated_at_gmt']) ? (string) $job['updated_at_gmt'] : '';
        $updated_ts = $updated !== '' ? strtotime($updated . ' GMT') : 0;
        $active[] = array(
            'job_key' => (string) $job_key,
            'status' => $status,
            'order_id' => isset($job['order_id']) ? absint($job['order_id']) : 0,
            'store_name' => isset($job['store_name']) ? (string) $job['store_name'] : '',
            'updated_at_gmt' => $updated,
            'updated_ts' => $updated_ts > 0 ? $updated_ts : 0,
        );
    }

    usort($active, function ($a, $b) {
        if ($a['updated_ts'] === $b['updated_ts']) {
            return strcmp((string) $a['job_key'], (string) $b['job_key']);
        }
        return $a['updated_ts'] < $b['updated_ts'] ? -1 : 1;
    });

    return $active;
}

function np_order_hub_print_agent_monitor_health() {
    $jobs = np_order_hub_print_queue_get_jobs();
    $active = np_order_hub_print_queue_get_active_jobs($jobs);
    $active_count = count($active);

    $heartbeat = np_order_hub_print_agent_get_heartbeat();
    $last_seen_gmt = isset($heartbeat['last_seen_gmt']) ? (string) $heartbeat['last_seen_gmt'] : '';
    $last_seen_ts = $last_seen_gmt !== '' ? strtotime($last_seen_gmt . ' GMT') : 0;
    $now = time();
    $heartbeat_age = $last_seen_ts > 0 ? max(0, $now - $last_seen_ts) : PHP_INT_MAX;

    $stale = $active_count > 0 && ($last_seen_ts < 1 || $heartbeat_age > NP_ORDER_HUB_PRINT_AGENT_STALE_SECONDS);

    $monitor = get_option(NP_ORDER_HUB_PRINT_AGENT_MONITOR_OPTION, array());
    if (!is_array($monitor)) {
        $monitor = array();
    }
    $alert_open = !empty($monitor['alert_open']);
    $last_alert_ts = isset($monitor['last_alert_ts']) ? (int) $monitor['last_alert_ts'] : 0;
    $cooldown = max(60, (int) NP_ORDER_HUB_PRINT_AGENT_ALERT_COOLDOWN_SECONDS);
    $changed = false;

    $title_base = 'Order Hub';
    if (function_exists('np_order_hub_get_pushover_settings')) {
        $settings = np_order_hub_get_pushover_settings();
        if (is_array($settings) && !empty($settings['title'])) {
            $title_base = (string) $settings['title'];
        }
    }

    if ($stale) {
        $should_alert = !$alert_open || ($now - $last_alert_ts) >= $cooldown;
        if ($should_alert) {
            $examples = array();
            foreach (array_slice($active, 0, 3) as $row) {
                $label = '#' . (int) $row['order_id'];
                if (!empty($row['store_name'])) {
                    $label .= ' ' . $row['store_name'];
                }
                $label .= ' [' . $row['status'] . ']';
                $examples[] = $label;
            }

            $message = 'Print-agent inaktiv. Aktive jobber i kø: ' . $active_count . '.';
            if (!empty($examples)) {
                $message .= ' Eksempler: ' . implode(', ', $examples) . '.';
            }

            if (function_exists('np_order_hub_send_pushover_message')) {
                np_order_hub_send_pushover_message($title_base . ' - Print Alert', $message);
            }
            $monitor['alert_open'] = 1;
            $monitor['last_alert_ts'] = $now;
            $monitor['last_alert_gmt'] = gmdate('Y-m-d H:i:s');
            $monitor['last_alert_active_count'] = $active_count;
            $monitor['last_alert_heartbeat_gmt'] = $last_seen_gmt;
            $changed = true;
        }
    } else {
        if ($alert_open) {
            $heartbeat_label = $last_seen_gmt !== '' ? get_date_from_gmt($last_seen_gmt, 'd.m.y H:i:s') : 'ukjent';
            $message = 'Print-agent er tilbake. Heartbeat: ' . $heartbeat_label . '. Aktive jobber i kø: ' . $active_count . '.';
            if (function_exists('np_order_hub_send_pushover_message')) {
                np_order_hub_send_pushover_message($title_base . ' - Print OK', $message);
            }
            $monitor['alert_open'] = 0;
            $monitor['last_recovered_ts'] = $now;
            $monitor['last_recovered_gmt'] = gmdate('Y-m-d H:i:s');
            $changed = true;
        }
    }

    if ($changed) {
        update_option(NP_ORDER_HUB_PRINT_AGENT_MONITOR_OPTION, $monitor, false);
    }
}

function np_order_hub_print_queue_cron_schedules($schedules) {
    if (!is_array($schedules)) {
        $schedules = array();
    }
    if (empty($schedules['np_order_hub_1min'])) {
        $schedules['np_order_hub_1min'] = array(
            'interval' => 60,
            'display' => 'Every minute (Order Hub)',
        );
    }
    return $schedules;
}

function np_order_hub_print_queue_schedule_tick() {
    if (!function_exists('wp_next_scheduled') || !function_exists('wp_schedule_event')) {
        return;
    }
    if (!wp_next_scheduled(NP_ORDER_HUB_PRINT_QUEUE_TICK_EVENT)) {
        wp_schedule_event(time() + 30, 'np_order_hub_1min', NP_ORDER_HUB_PRINT_QUEUE_TICK_EVENT);
    }
}

function np_order_hub_print_queue_tick() {
    np_order_hub_print_queue_release_stale_printing_jobs();
    np_order_hub_print_queue_run_due_jobs(20);
    np_order_hub_print_agent_monitor_health();
}

add_filter('cron_schedules', 'np_order_hub_print_queue_cron_schedules');
add_action('init', 'np_order_hub_print_queue_schedule_tick');
add_action('rest_api_init', 'np_order_hub_register_routes');
add_action(NP_ORDER_HUB_PRINT_QUEUE_EVENT, 'np_order_hub_process_print_job', 10, 1);
add_action(NP_ORDER_HUB_PRINT_QUEUE_TICK_EVENT, 'np_order_hub_print_queue_tick');

function np_order_hub_register_routes() {
    register_rest_route('np-order-hub/v1', '/webhook', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_handle_webhook',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/store-connect', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_rest_store_connect',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/help-scout-webhook', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_handle_help_scout_webhook',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/print-agent/claim', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_print_agent_claim',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/print-agent/finish', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_print_agent_finish',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/production-error', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_handle_production_error',
        'permission_callback' => '__return_true',
    ));
}

function np_order_hub_print_agent_claim(WP_REST_Request $request) {
    if (!np_order_hub_print_agent_is_authorized($request)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }

    $agent_name = sanitize_text_field((string) $request->get_param('agent'));
    // Make sure due jobs are materialized into "ready" PDFs before claim.
    np_order_hub_print_queue_run_due_jobs(10);
    $job = np_order_hub_print_queue_claim_next_ready_job($agent_name);
    if (!is_array($job) || empty($job['job_key'])) {
        np_order_hub_print_agent_update_heartbeat($agent_name, 'claim', array('status' => 'empty'));
        np_order_hub_print_agent_monitor_health();
        return new WP_REST_Response(array(
            'status' => 'empty',
            'server_time_gmt' => gmdate('Y-m-d H:i:s'),
        ), 200);
    }

    np_order_hub_print_agent_update_heartbeat($agent_name, 'claim', array(
        'status' => 'claimed',
        'job_key' => (string) $job['job_key'],
    ));
    np_order_hub_print_agent_monitor_health();

    return new WP_REST_Response(array(
        'status' => 'claimed',
        'job' => $job,
        'server_time_gmt' => gmdate('Y-m-d H:i:s'),
    ), 200);
}

function np_order_hub_print_agent_finish(WP_REST_Request $request) {
    if (!np_order_hub_print_agent_is_authorized($request)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }

    $job_key = sanitize_text_field((string) $request->get_param('job_key'));
    $claim_id = sanitize_text_field((string) $request->get_param('claim_id'));
    $success_raw = $request->get_param('success');
    $success = filter_var($success_raw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($success === null) {
        $status_raw = sanitize_key((string) $request->get_param('status'));
        $success = in_array($status_raw, array('done', 'ok', 'success', 'printed', 'completed'), true);
    }
    $error_message = sanitize_text_field((string) $request->get_param('error'));
    $result = np_order_hub_print_queue_finish_claimed_job($job_key, $claim_id, (bool) $success, $error_message);
    np_order_hub_print_agent_update_heartbeat('', 'finish', array(
        'status' => $success ? 'success' : 'failed',
        'job_key' => $job_key,
    ));
    np_order_hub_print_agent_monitor_health();
    if (is_wp_error($result)) {
        return new WP_REST_Response(array(
            'error' => $result->get_error_message(),
            'code' => $result->get_error_code(),
        ), 400);
    }

    return new WP_REST_Response(array(
        'status' => 'ok',
        'job' => $result,
        'server_time_gmt' => gmdate('Y-m-d H:i:s'),
    ), 200);
}

function np_order_hub_handle_production_error(WP_REST_Request $request) {
    np_order_hub_ensure_production_error_table();

    $store_key = sanitize_key((string) $request->get_param('store'));
    if ($store_key === '') {
        return new WP_REST_Response(array('error' => 'missing_store'), 400);
    }

    $store = np_order_hub_get_store_by_key($store_key);
    if (!is_array($store)) {
        return new WP_REST_Response(array('error' => 'store_not_found'), 404);
    }

    $body = (string) $request->get_body();
    $signature = (string) $request->get_header('X-WC-Webhook-Signature');
    $token = (string) $request->get_header('x-np-order-hub-token');
    if ($token === '') {
        $token = (string) $request->get_param('token');
    }

    $authorized = false;
    if ($signature !== '' && np_order_hub_verify_store_signature($body, $signature, $store)) {
        $authorized = true;
    }
    if (!$authorized && $token !== '') {
        $expected_token = isset($store['token']) ? (string) $store['token'] : '';
        if ($expected_token !== '' && hash_equals($expected_token, $token)) {
            $authorized = true;
        }
    }
    if (!$authorized) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        $data = $request->get_params();
    }
    if (!is_array($data)) {
        return new WP_REST_Response(array('error' => 'invalid_payload'), 400);
    }

    $quantity = absint($data['quantity'] ?? 1);
    if ($quantity < 1) {
        $quantity = 1;
    }

    $unit_cost = np_order_hub_parse_numeric_value($data['unit_cost'] ?? null);
    if ($unit_cost === null || $unit_cost < 0) {
        $unit_cost = 0.0;
    }
    $total_cost = np_order_hub_parse_numeric_value($data['total_cost'] ?? null);
    if ($total_cost === null || $total_cost < 0) {
        $total_cost = $unit_cost * $quantity;
    }

    $product_id = absint($data['product_id'] ?? 0);
    $variation_id = absint($data['variation_id'] ?? 0);
    $product_name = sanitize_text_field((string) ($data['product_name'] ?? ''));
    if ($product_name === '' && $product_id > 0) {
        $product_name = 'Product #' . $product_id;
    }
    if ($product_name === '') {
        $product_name = 'Product';
    }

    $size_label = sanitize_text_field((string) ($data['size_label'] ?? ''));
    $sku = sanitize_text_field((string) ($data['sku'] ?? ''));
    $currency = strtoupper(sanitize_text_field((string) ($data['currency'] ?? '')));
    if ($currency === '') {
        $currency = 'NOK';
    }
	    $source = sanitize_key((string) ($data['source'] ?? NP_ORDER_HUB_PRODUCTION_ERROR_SOURCE_QR));
	    $error_type = np_order_hub_normalize_production_error_type($data['error_type'] ?? 'trykkfeil');
	    $note = sanitize_textarea_field((string) ($data['note'] ?? ''));
	    $stock_before = np_order_hub_parse_numeric_value($data['stock_before'] ?? null);
	    $stock_after = np_order_hub_parse_numeric_value($data['stock_after'] ?? null);

    global $wpdb;
    $table = np_order_hub_production_error_table_name();
    $now_gmt = current_time('mysql', true);
    $row = array(
        'store_key' => $store_key,
        'store_name' => sanitize_text_field((string) ($store['name'] ?? $store_key)),
        'store_url' => esc_url_raw((string) ($store['url'] ?? '')),
        'product_id' => $product_id,
        'variation_id' => $variation_id,
        'product_name' => $product_name,
        'size_label' => $size_label,
        'sku' => $sku,
        'quantity' => $quantity,
        'unit_cost' => $unit_cost,
        'total_cost' => $total_cost,
        'currency' => $currency,
	        'stock_before' => $stock_before,
	        'stock_after' => $stock_after,
	        'source' => $source,
	        'error_type' => $error_type,
	        'note' => $note,
	        'payload' => wp_json_encode($data),
	        'created_at_gmt' => $now_gmt,
        'updated_at_gmt' => $now_gmt,
    );

    $inserted = $wpdb->insert(
        $table,
        $row,
	        array(
	            '%s', '%s', '%s', '%d', '%d',
	            '%s', '%s', '%s', '%d', '%f',
	            '%f', '%s', '%f', '%f', '%s',
	            '%s', '%s', '%s', '%s', '%s',
	        )
	    );

    if ($inserted === false) {
        error_log('[np-order-hub] production_error_insert_failed ' . wp_json_encode(array(
            'store_key' => $store_key,
            'db_error' => $wpdb->last_error,
        )));
        return new WP_REST_Response(array('error' => 'db_insert_failed'), 500);
    }

    return new WP_REST_Response(array(
        'status' => 'ok',
        'id' => (int) $wpdb->insert_id,
    ), 200);
}
