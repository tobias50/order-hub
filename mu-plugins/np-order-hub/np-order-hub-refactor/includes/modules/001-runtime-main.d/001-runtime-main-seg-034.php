<?php
function np_order_hub_should_notify_new_order_status($status) {
    $status = sanitize_key((string) $status);
    return $status === 'processing';
}

function np_order_hub_try_notify_new_order($store, $order_number, $order_id, $status, $total, $currency, $is_special_order = false, $previous_status = '') {
    $store_key = is_array($store) && !empty($store['key']) ? (string) $store['key'] : '';
    $settings = np_order_hub_get_pushover_settings();
    if (empty($settings['enabled']) || $settings['user'] === '' || $settings['token'] === '') {
        np_order_hub_log('pushover_new_order_skipped_missing_config', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
        ));
        return false;
    }

    if ($is_special_order) {
        np_order_hub_log('pushover_new_order_skipped_special_order', array(
            'store_key' => $store_key,
            'order_id' => (int) $order_id,
            'order_number' => (string) $order_number,
            'status' => sanitize_key((string) $status),
        ));
        return false;
    }

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

    $store_name = is_array($store) && !empty($store['name']) ? (string) $store['name'] : 'Store';
    $total_display = np_order_hub_format_money((float) $total, (string) $currency);
    $message = $store_name . "\n" . $total_display;

    return np_order_hub_send_pushover_message('Ny ordre', $message, array(
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
}
