<?php
function np_order_hub_should_notify_new_order_status($status) {
    $status = sanitize_key((string) $status);
    return $status === 'processing';
}

function np_order_hub_get_processing_notification_row($store_key, $order_id) {
    global $wpdb;

    $store_key = sanitize_key((string) $store_key);
    $order_id = absint($order_id);
    if ($store_key === '' || $order_id < 1 || !isset($wpdb) || !($wpdb instanceof wpdb)) {
        return null;
    }

    np_order_hub_ensure_order_notification_columns();

    $table = np_order_hub_table_name();
    return $wpdb->get_row(
        $wpdb->prepare(
            "SELECT id, processing_notify_state, processing_notified_at_gmt, processing_notify_attempts, processing_notify_last_attempt_gmt, processing_notify_last_error
             FROM $table
             WHERE store_key = %s AND order_id = %d
             LIMIT 1",
            $store_key,
            $order_id
        ),
        ARRAY_A
    );
}

function np_order_hub_update_processing_notification_tracking($store_key, $order_id, $state, $error = '', $increment_attempt = false, $set_sent = false) {
    global $wpdb;

    $store_key = sanitize_key((string) $store_key);
    $order_id = absint($order_id);
    $state = sanitize_key((string) $state);
    if ($store_key === '' || $order_id < 1 || !isset($wpdb) || !($wpdb instanceof wpdb)) {
        return false;
    }

    np_order_hub_ensure_order_notification_columns();

    $table = np_order_hub_table_name();
    $now_gmt = gmdate('Y-m-d H:i:s');
    $error = trim((string) $error);
    if (strlen($error) > 65000) {
        $error = substr($error, 0, 65000);
    }

    $last_error_sql = $error !== '' ? '%s' : 'NULL';
    $sent_sql = $set_sent ? '%s' : 'NULL';
    $sql = "
        UPDATE $table
        SET processing_notify_state = %s,
            processing_notify_last_error = {$last_error_sql},
            processing_notify_last_attempt_gmt = %s,
            processing_notify_attempts = processing_notify_attempts + %d,
            processing_notified_at_gmt = {$sent_sql}
        WHERE store_key = %s
          AND order_id = %d
    ";

    $args = array($state);
    if ($error !== '') {
        $args[] = $error;
    }
    $args[] = $now_gmt;
    $args[] = $increment_attempt ? 1 : 0;
    if ($set_sent) {
        $args[] = $now_gmt;
    }
    $args[] = $store_key;
    $args[] = $order_id;

    $result = $wpdb->query($wpdb->prepare($sql, $args));

    return $result !== false;
}

function np_order_hub_get_last_pushover_error_message() {
    $result = function_exists('np_order_hub_get_last_pushover_result') ? np_order_hub_get_last_pushover_result() : array();
    $code = sanitize_key((string) ($result['code'] ?? ''));
    $message = trim((string) ($result['message'] ?? ''));

    if ($message !== '') {
        return $code !== '' ? $code . ': ' . $message : $message;
    }

    return $code !== '' ? $code : 'send_failed';
}

function np_order_hub_order_payload_is_special($payload) {
    if (!is_array($payload)) {
        return false;
    }

    $status = sanitize_key((string) ($payload['status'] ?? ''));
    return !empty($payload['np_reklamasjon'])
        || !empty($payload['np_reklamasjon_source_order'])
        || !empty($payload['np_bytte_storrelse'])
        || !empty($payload['np_bytte_storrelse_source_order'])
        || in_array($status, array('reklamasjon', 'bytte-storrelse'), true);
}

function np_order_hub_try_notify_new_order($store, $order_number, $order_id, $status, $total, $currency, $is_special_order = false, $previous_status = '') {
    $store_key = is_array($store) && !empty($store['key']) ? (string) $store['key'] : '';
    $tracking = np_order_hub_get_processing_notification_row($store_key, $order_id);
    $tracking_state = sanitize_key((string) ($tracking['processing_notify_state'] ?? ''));
    $normalized_status = sanitize_key((string) $status);
    if (!np_order_hub_should_notify_new_order_status($normalized_status)) {
        np_order_hub_log('pushover_new_order_skipped_status', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
            'status' => $normalized_status,
        ));
        return false;
    }

    $normalized_previous_status = sanitize_key((string) $previous_status);
    if (in_array($tracking_state, array('sent', 'skipped'), true)) {
        np_order_hub_log('pushover_new_order_skipped_already_resolved', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
            'status' => $normalized_status,
            'tracking_state' => $tracking_state,
        ));
        return false;
    }
    if ($normalized_previous_status !== '' && np_order_hub_should_notify_new_order_status($normalized_previous_status)) {
        np_order_hub_log('pushover_new_order_skipped_duplicate', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
            'status' => $normalized_status,
            'previous_status' => $normalized_previous_status,
        ));
        return false;
    }

    $settings = np_order_hub_get_pushover_settings();
    if (empty($settings['enabled']) || $settings['user'] === '' || $settings['token'] === '') {
        np_order_hub_update_processing_notification_tracking($store_key, $order_id, 'pending', 'missing_config', true, false);
        np_order_hub_log('pushover_new_order_skipped_missing_config', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
        ));
        return false;
    }

    if ($is_special_order) {
        np_order_hub_update_processing_notification_tracking($store_key, $order_id, 'skipped', 'special_order', true, false);
        np_order_hub_log('pushover_new_order_skipped_special_order', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
            'status' => sanitize_key((string) $status),
        ));
        return false;
    }

    $store_name = is_array($store) && !empty($store['name']) ? (string) $store['name'] : 'Store';
    $total_display = np_order_hub_format_money((float) $total, (string) $currency);
    $message = $store_name . "\n" . $total_display;

    np_order_hub_update_processing_notification_tracking($store_key, $order_id, 'pending', '', true, false);

    $sent = np_order_hub_send_pushover_message('Ny ordre', $message, array(
        'type' => 'new_order',
        'store_key' => $store_key,
        'store_name' => $store_name,
        'order_id' => (int) $order_id,
        'order_number' => (string) $order_number,
        'status' => $normalized_status,
        'previous_status' => $normalized_previous_status,
        'total' => (float) $total,
        'currency' => (string) $currency,
    ));

    if ($sent) {
        np_order_hub_update_processing_notification_tracking($store_key, $order_id, 'sent', '', false, true);
        return true;
    }

    np_order_hub_update_processing_notification_tracking(
        $store_key,
        $order_id,
        'pending',
        np_order_hub_get_last_pushover_error_message(),
        false,
        false
    );

    return false;
}

function np_order_hub_retry_processing_notifications($limit = 25) {
    global $wpdb;

    $limit = max(1, min(250, absint($limit)));
    if (!isset($wpdb) || !($wpdb instanceof wpdb)) {
        return array('checked' => 0, 'sent' => 0, 'skipped' => 0, 'failed' => 0);
    }

    np_order_hub_ensure_order_notification_columns();

    $table = np_order_hub_table_name();
    $retry_before = gmdate('Y-m-d H:i:s', time() - 120);
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT store_key, store_name, order_id, order_number, status, currency, total, payload, processing_notify_state
             FROM $table
             WHERE status = %s
               AND processing_notify_state = %s
               AND (
                    processing_notify_last_attempt_gmt IS NULL
                    OR processing_notify_last_attempt_gmt <= %s
               )
             ORDER BY COALESCE(date_modified_gmt, updated_at_gmt, created_at_gmt) DESC
             LIMIT %d",
            'processing',
            'pending',
            $retry_before,
            $limit
        ),
        ARRAY_A
    );

    $stats = array(
        'checked' => 0,
        'sent' => 0,
        'skipped' => 0,
        'failed' => 0,
    );

    foreach ((array) $rows as $row) {
        $stats['checked']++;
        $payload = json_decode((string) ($row['payload'] ?? ''), true);
        $is_special_order = np_order_hub_order_payload_is_special($payload);
        $store_key = sanitize_key((string) ($row['store_key'] ?? ''));
        $store = np_order_hub_get_store_by_key($store_key);
        if (!is_array($store)) {
            $store = array(
                'key' => $store_key,
                'name' => (string) ($row['store_name'] ?? 'Store'),
            );
        }

        $sent = np_order_hub_try_notify_new_order(
            $store,
            (string) ($row['order_number'] ?? ''),
            (int) ($row['order_id'] ?? 0),
            (string) ($row['status'] ?? ''),
            (float) ($row['total'] ?? 0),
            (string) ($row['currency'] ?? ''),
            $is_special_order,
            ''
        );

        if ($sent) {
            $stats['sent']++;
            continue;
        }

        $state_after = np_order_hub_get_processing_notification_row($store_key, (int) ($row['order_id'] ?? 0));
        $resolved_state = sanitize_key((string) ($state_after['processing_notify_state'] ?? ''));
        if ($resolved_state === 'skipped') {
            $stats['skipped']++;
        } else {
            $stats['failed']++;
        }
    }

    if ($stats['checked'] > 0) {
        np_order_hub_log('processing_notification_retry_run', $stats);
    }

    return $stats;
}
