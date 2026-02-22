<?php
function np_order_hub_wpo_get_order_from_webhook_arg($arg) {
    if (!function_exists('wc_get_order')) {
        return null;
    }
    if (is_a($arg, 'WC_Order')) {
        return $arg;
    }
    if (is_array($arg)) {
        if (!empty($arg['order']) && is_a($arg['order'], 'WC_Order')) {
            return $arg['order'];
        }
        $resource = isset($arg['resource']) ? (string) $arg['resource'] : '';
        if ($resource !== '' && $resource !== 'order') {
            return null;
        }
        $order_id = 0;
        if (!empty($arg['resource_id'])) {
            $order_id = absint($arg['resource_id']);
        } elseif (!empty($arg['id'])) {
            $order_id = absint($arg['id']);
        }
        if ($order_id > 0) {
            return wc_get_order($order_id);
        }
    }
    if (is_object($arg) && method_exists($arg, 'get_id')) {
        $order_id = (int) $arg->get_id();
        if ($order_id > 0) {
            return wc_get_order($order_id);
        }
    }
    return null;
}

function np_order_hub_wpo_should_force_hub_delivery($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return false;
    }
    $status = method_exists($order, 'get_status') ? (string) $order->get_status() : '';
    if ($status === 'restordre') {
        return true;
    }
    return (bool) $order->get_meta('_np_order_hub_force_send', true);
}

function np_order_hub_wpo_maybe_disable_hub_webhook($should_deliver, $webhook = null, $arg = null) {
    if (!$should_deliver) {
        return $should_deliver;
    }
    if (!np_order_hub_wpo_is_hub_disabled()) {
        return $should_deliver;
    }
    if (np_order_hub_wpo_is_hub_webhook($webhook)) {
        $order = np_order_hub_wpo_get_order_from_webhook_arg($arg);
        if ($order && np_order_hub_wpo_should_force_hub_delivery($order)) {
            return $should_deliver;
        }
        np_order_hub_wpo_log('webhook_delivery_skipped', array(
            'delivery_url' => is_object($webhook) && method_exists($webhook, 'get_delivery_url') ? (string) $webhook->get_delivery_url() : '',
            'order_id' => $order && method_exists($order, 'get_id') ? (int) $order->get_id() : 0,
        ));
        return false;
    }
    return $should_deliver;
}

function np_order_hub_wpo_direct_push_lock_key($order_id, $event = '') {
    $order_id = absint($order_id);
    $event = sanitize_key((string) $event);
    if ($event !== '') {
        return NP_ORDER_HUB_WPO_DIRECT_PUSH_LOCK_PREFIX . $order_id . '_' . $event;
    }
    return NP_ORDER_HUB_WPO_DIRECT_PUSH_LOCK_PREFIX . $order_id;
}

function np_order_hub_wpo_acquire_direct_push_lock($order_id, $event = '') {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return false;
    }
    $key = np_order_hub_wpo_direct_push_lock_key($order_id, $event);
    if (get_transient($key)) {
        return false;
    }
    set_transient($key, '1', 60);
    return true;
}

function np_order_hub_wpo_release_direct_push_lock($order_id, $event = '') {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return;
    }
    delete_transient(np_order_hub_wpo_direct_push_lock_key($order_id, $event));
}

function np_order_hub_wpo_get_active_webhook_ids() {
    $ids = array();

    global $wpdb;
    if (isset($wpdb) && is_object($wpdb) && !empty($wpdb->prefix)) {
        $table = $wpdb->prefix . 'wc_webhooks';
        $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
        if (is_string($table_exists) && $table_exists === $table) {
            $table_ids = $wpdb->get_col("SELECT webhook_id FROM {$table} WHERE status = 'active'");
            if (is_array($table_ids)) {
                foreach ($table_ids as $candidate_id) {
                    $candidate_id = absint($candidate_id);
                    if ($candidate_id > 0) {
                        $ids[$candidate_id] = true;
                    }
                }
            }
        }
    }

    $post_ids = get_posts(array(
        'post_type' => 'shop_webhook',
        'post_status' => 'publish',
        'numberposts' => -1,
        'fields' => 'ids',
        'no_found_rows' => true,
        'suppress_filters' => true,
    ));
    if (is_array($post_ids)) {
        foreach ($post_ids as $post_id) {
            $post_id = absint($post_id);
            if ($post_id > 0) {
                $ids[$post_id] = true;
            }
        }
    }

    return array_map('absint', array_keys($ids));
}

function np_order_hub_wpo_get_hub_webhook_targets() {
    $targets = array();
    if (!class_exists('WC_Webhook')) {
        return $targets;
    }

    $webhook_ids = np_order_hub_wpo_get_active_webhook_ids();
    if (!is_array($webhook_ids) || empty($webhook_ids)) {
        return $targets;
    }

    foreach ($webhook_ids as $webhook_id) {
        $webhook = new WC_Webhook((int) $webhook_id);
        if (!$webhook || !is_a($webhook, 'WC_Webhook')) {
            continue;
        }
        if (!np_order_hub_wpo_is_hub_webhook($webhook)) {
            continue;
        }
        $status = method_exists($webhook, 'get_status') ? (string) $webhook->get_status() : '';
        if ($status !== '' && $status !== 'active') {
            continue;
        }
        $topic = method_exists($webhook, 'get_topic') ? strtolower((string) $webhook->get_topic()) : '';
        if ($topic !== '' && strpos($topic, 'order.') !== 0 && strpos($topic, 'action.woocommerce_') !== 0) {
            continue;
        }
        $delivery_url = method_exists($webhook, 'get_delivery_url') ? (string) $webhook->get_delivery_url() : '';
        if ($delivery_url === '') {
            continue;
        }
        $targets[] = array(
            'id' => (int) $webhook->get_id(),
            'delivery_url' => $delivery_url,
            'topic' => $topic !== '' ? $topic : 'order.created',
            'secret' => method_exists($webhook, 'get_secret') ? (string) $webhook->get_secret() : '',
        );
    }

    return $targets;
}

function np_order_hub_wpo_iso_datetime($date, $gmt = false) {
    if (!$date || !is_a($date, 'WC_DateTime')) {
        return '';
    }
    $timestamp = $date->getTimestamp();
    if ($timestamp <= 0) {
        return '';
    }
    if ($gmt) {
        return gmdate('Y-m-d\\TH:i:s', $timestamp);
    }
    return wp_date('Y-m-d\\TH:i:s', $timestamp);
}

function np_order_hub_wpo_get_rest_order_payload($order) {
    if (!$order || !is_a($order, 'WC_Order') || !class_exists('WP_REST_Request')) {
        return null;
    }

    $candidates = array(
        'WC_REST_Orders_V3_Controller',
        'WC_REST_Orders_V2_Controller',
    );
    foreach ($candidates as $class_name) {
        if (!class_exists($class_name)) {
            continue;
        }
        $controller = new $class_name();
        if (!method_exists($controller, 'prepare_object_for_response')) {
            continue;
        }
        $request = new WP_REST_Request('GET');
        $request->set_param('context', 'view');
        $response = $controller->prepare_object_for_response($order, $request);
        if (!is_object($response) || !method_exists($response, 'get_data')) {
            continue;
        }
        $payload = $response->get_data();
        if (is_array($payload) && !empty($payload['id'])) {
            return $payload;
        }
    }

    return null;
}

function np_order_hub_wpo_get_fallback_order_payload($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return array();
    }

    $line_items = array();
    foreach ($order->get_items('line_item') as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }
        $product = $item->get_product();
        $line_items[] = array(
            'id' => (int) $item_id,
            'name' => (string) $item->get_name(),
            'product_id' => (int) $item->get_product_id(),
            'variation_id' => (int) $item->get_variation_id(),
            'quantity' => (int) $item->get_quantity(),
            'tax_class' => (string) $item->get_tax_class(),
            'subtotal' => wc_format_decimal((float) $item->get_subtotal(), wc_get_price_decimals()),
            'subtotal_tax' => wc_format_decimal((float) $item->get_subtotal_tax(), wc_get_price_decimals()),
            'total' => wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
            'total_tax' => wc_format_decimal((float) $item->get_total_tax(), wc_get_price_decimals()),
            'sku' => $product ? (string) $product->get_sku() : '',
            'price' => (int) $item->get_quantity() > 0
                ? wc_format_decimal(((float) $item->get_total() / max(1, (int) $item->get_quantity())), wc_get_price_decimals())
                : wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
        );
    }

    $shipping_lines = array();
    foreach ($order->get_items('shipping') as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Shipping')) {
            continue;
        }
        $shipping_lines[] = array(
            'id' => (int) $item_id,
            'method_title' => (string) $item->get_name(),
            'method_id' => (string) $item->get_method_id(),
            'instance_id' => (string) $item->get_instance_id(),
            'total' => wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
            'total_tax' => wc_format_decimal((float) $item->get_total_tax(), wc_get_price_decimals()),
        );
    }

    $fee_lines = array();
    foreach ($order->get_items('fee') as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Fee')) {
            continue;
        }
        $fee_lines[] = array(
            'id' => (int) $item_id,
            'name' => (string) $item->get_name(),
            'tax_class' => (string) $item->get_tax_class(),
            'tax_status' => (string) $item->get_tax_status(),
            'total' => wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
            'total_tax' => wc_format_decimal((float) $item->get_total_tax(), wc_get_price_decimals()),
        );
    }

    $coupon_lines = array();
    foreach ($order->get_items('coupon') as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Coupon')) {
            continue;
        }
        $coupon_lines[] = array(
            'id' => (int) $item_id,
            'code' => (string) $item->get_code(),
            'discount' => wc_format_decimal((float) $item->get_discount(), wc_get_price_decimals()),
            'discount_tax' => wc_format_decimal((float) $item->get_discount_tax(), wc_get_price_decimals()),
        );
    }

    $meta_data = array();
    foreach ($order->get_meta_data() as $meta) {
        if (!is_object($meta) || !method_exists($meta, 'get_data')) {
            continue;
        }
        $meta_row = $meta->get_data();
        if (!is_array($meta_row) || !isset($meta_row['key'])) {
            continue;
        }
        $meta_data[] = array(
            'id' => isset($meta_row['id']) ? (int) $meta_row['id'] : 0,
            'key' => (string) $meta_row['key'],
            'value' => isset($meta_row['value']) ? $meta_row['value'] : '',
        );
    }

    $customer_id = method_exists($order, 'get_customer_id') ? (int) $order->get_customer_id() : 0;

    return array(
        'id' => (int) $order->get_id(),
        'parent_id' => (int) $order->get_parent_id(),
        'status' => (string) $order->get_status(),
        'currency' => (string) $order->get_currency(),
        'version' => (string) $order->get_version(),
        'prices_include_tax' => (bool) $order->get_prices_include_tax(),
        'date_created' => np_order_hub_wpo_iso_datetime($order->get_date_created(), false),
        'date_created_gmt' => np_order_hub_wpo_iso_datetime($order->get_date_created(), true),
        'date_modified' => np_order_hub_wpo_iso_datetime($order->get_date_modified(), false),
        'date_modified_gmt' => np_order_hub_wpo_iso_datetime($order->get_date_modified(), true),
        'discount_total' => wc_format_decimal((float) $order->get_discount_total(), wc_get_price_decimals()),
        'discount_tax' => wc_format_decimal((float) $order->get_discount_tax(), wc_get_price_decimals()),
        'shipping_total' => wc_format_decimal((float) $order->get_shipping_total(), wc_get_price_decimals()),
        'shipping_tax' => wc_format_decimal((float) $order->get_shipping_tax(), wc_get_price_decimals()),
        'cart_tax' => wc_format_decimal((float) $order->get_cart_tax(), wc_get_price_decimals()),
        'total' => wc_format_decimal((float) $order->get_total(), wc_get_price_decimals()),
        'total_tax' => wc_format_decimal((float) $order->get_total_tax(), wc_get_price_decimals()),
        'customer_id' => $customer_id,
        'order_key' => (string) $order->get_order_key(),
        'billing' => is_array($order->get_address('billing')) ? $order->get_address('billing') : array(),
        'shipping' => is_array($order->get_address('shipping')) ? $order->get_address('shipping') : array(),
        'payment_method' => (string) $order->get_payment_method(),
        'payment_method_title' => (string) $order->get_payment_method_title(),
        'transaction_id' => (string) $order->get_transaction_id(),
        'customer_ip_address' => (string) $order->get_customer_ip_address(),
        'customer_user_agent' => (string) $order->get_customer_user_agent(),
        'created_via' => (string) $order->get_created_via(),
        'customer_note' => (string) $order->get_customer_note(),
        'date_completed' => np_order_hub_wpo_iso_datetime($order->get_date_completed(), false),
        'date_completed_gmt' => np_order_hub_wpo_iso_datetime($order->get_date_completed(), true),
        'date_paid' => np_order_hub_wpo_iso_datetime($order->get_date_paid(), false),
        'date_paid_gmt' => np_order_hub_wpo_iso_datetime($order->get_date_paid(), true),
        'cart_hash' => (string) $order->get_cart_hash(),
        'number' => (string) $order->get_order_number(),
        'meta_data' => $meta_data,
        'line_items' => $line_items,
        'shipping_lines' => $shipping_lines,
        'fee_lines' => $fee_lines,
        'coupon_lines' => $coupon_lines,
    );
}