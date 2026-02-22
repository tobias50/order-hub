<?php
/**
 * Plugin Name: NP Order Hub - WPO Access Key
 * Description: Adds packing slip access data to WooCommerce webhooks and exposes token-protected packing slip endpoints.
 * Version: 0.2.10
 * Author: Nordicprofil
 */

if (!defined('ABSPATH')) {
    exit;
}

add_filter('woocommerce_webhook_payload', 'np_order_hub_add_wpo_access_key', 10, 4);
add_filter('woocommerce_webhook_should_deliver', 'np_order_hub_wpo_maybe_disable_hub_webhook', 10, 3);
add_filter('pre_wp_mail', 'np_order_hub_wpo_maybe_disable_outgoing_email', 10, 2);
add_action('woocommerce_new_order', 'np_order_hub_wpo_push_new_order_to_hub', 20, 1);
add_action('woocommerce_update_order', 'np_order_hub_wpo_push_order_update_to_hub', 30, 2);
add_action('woocommerce_order_status_changed', 'np_order_hub_wpo_push_order_status_change_to_hub', 30, 4);
add_action('woocommerce_before_trash_order', 'np_order_hub_wpo_push_order_before_trash_to_hub', 30, 2);
add_action('woocommerce_trash_order', 'np_order_hub_wpo_push_order_trash_to_hub', 30, 1);
add_action('woocommerce_untrash_order', 'np_order_hub_wpo_push_order_untrash_to_hub', 30, 2);
add_action('woocommerce_before_delete_order', 'np_order_hub_wpo_push_order_before_delete_to_hub', 30, 2);
add_action('woocommerce_delete_order', 'np_order_hub_wpo_push_order_delete_to_hub', 30, 1);
add_action('woocommerce_order_refunded', 'np_order_hub_wpo_push_order_refunded_to_hub', 30, 2);
add_action('woocommerce_refund_deleted', 'np_order_hub_wpo_push_order_refund_deleted_to_hub', 30, 2);
add_action('rest_api_init', 'np_order_hub_wpo_register_routes');
add_action('admin_menu', 'np_order_hub_wpo_admin_menu');
add_action('add_meta_boxes', 'np_order_hub_wpo_add_reklamasjon_meta_box');
add_action('add_meta_boxes_woocommerce_page_wc-orders', 'np_order_hub_wpo_add_reklamasjon_meta_box_hpos');
add_action('admin_init', 'np_order_hub_wpo_handle_reklamasjon_create');
add_action('admin_notices', 'np_order_hub_wpo_reklamasjon_admin_notice');
add_action('add_meta_boxes', 'np_order_hub_wpo_add_oos_meta_box');
add_action('add_meta_boxes_woocommerce_page_wc-orders', 'np_order_hub_wpo_add_oos_meta_box_hpos');
add_action('admin_init', 'np_order_hub_wpo_handle_oos_create');
add_action('admin_notices', 'np_order_hub_wpo_oos_admin_notice');
add_action('init', 'np_order_hub_wpo_register_reklamasjon_status');
add_filter('wc_order_statuses', 'np_order_hub_wpo_add_reklamasjon_status', 20, 1);
add_action('init', 'np_order_hub_wpo_register_restordre_status');
add_filter('wc_order_statuses', 'np_order_hub_wpo_add_restordre_status', 20, 1);
add_action('woocommerce_order_status_changed', 'np_order_hub_wpo_mark_restordre_for_hub', 10, 4);
add_filter('wc_order_is_editable', 'np_order_hub_wpo_order_is_editable', 10, 2);

register_activation_hook(__FILE__, 'np_order_hub_wpo_activate');

define('NP_ORDER_HUB_WPO_TOKEN_OPTION', 'np_order_hub_wpo_token');
define('NP_ORDER_HUB_WPO_DISABLE_HUB_OPTION', 'np_order_hub_wpo_disable_hub');
define('NP_ORDER_HUB_WPO_DISABLE_EMAIL_OPTION', 'np_order_hub_wpo_disable_email');
define('NP_ORDER_HUB_WPO_DELIVERY_BUCKET_OPTION', 'np_order_hub_wpo_delivery_bucket');
define('NP_ORDER_HUB_WPO_DIRECT_PUSH_LOCK_PREFIX', 'np_order_hub_wpo_direct_push_');

function np_order_hub_wpo_log($message, $context = array()) {
    if (!is_array($context)) {
        $context = array('value' => $context);
    }
    $json = wp_json_encode($context);
    $line = $message;
    if (is_string($json) && $json !== '') {
        $line .= ' ' . $json;
    }
    if (function_exists('wc_get_logger')) {
        $logger = wc_get_logger();
        $logger->info($line, array('source' => 'np-order-hub-wpo'));
        return;
    }
    error_log('[np-order-hub-wpo] ' . $line);
}

function np_order_hub_wpo_activate() {
    np_order_hub_wpo_ensure_token();
}

function np_order_hub_wpo_generate_token() {
    return wp_generate_password(40, false, false);
}

function np_order_hub_wpo_ensure_token() {
    $token = get_option(NP_ORDER_HUB_WPO_TOKEN_OPTION, '');
    if (!is_string($token) || $token === '') {
        $token = np_order_hub_wpo_generate_token();
        update_option(NP_ORDER_HUB_WPO_TOKEN_OPTION, $token);
    }
    return $token;
}

function np_order_hub_wpo_get_token() {
    return np_order_hub_wpo_ensure_token();
}

function np_order_hub_wpo_check_token($token) {
    $expected = np_order_hub_wpo_get_token();
    if (!is_string($expected) || $expected === '') {
        return false;
    }
    return hash_equals($expected, (string) $token);
}

function np_order_hub_wpo_normalize_delivery_bucket($bucket) {
    $bucket = sanitize_key((string) $bucket);
    if ($bucket === 'scheduled') {
        return 'scheduled';
    }
    if ($bucket === 'standard') {
        return 'standard';
    }
    return '';
}

function np_order_hub_wpo_get_default_delivery_bucket() {
    $bucket = get_option(NP_ORDER_HUB_WPO_DELIVERY_BUCKET_OPTION, 'standard');
    $bucket = np_order_hub_wpo_normalize_delivery_bucket($bucket);
    return $bucket !== '' ? $bucket : 'standard';
}

function np_order_hub_wpo_register_reklamasjon_status() {
    register_post_status('wc-reklamasjon', array(
        'label' => _x('Reklamasjon', 'Order status', 'woocommerce'),
        'public' => true,
        'exclude_from_search' => false,
        'show_in_admin_status_list' => true,
        'show_in_admin_all_list' => true,
        'label_count' => _n_noop('Reklamasjon <span class="count">(%s)</span>', 'Reklamasjon <span class="count">(%s)</span>', 'woocommerce'),
    ));
}

function np_order_hub_wpo_add_reklamasjon_status($statuses) {
    $new_statuses = array();
    foreach ((array) $statuses as $key => $label) {
        $new_statuses[$key] = $label;
        if ($key === 'wc-processing') {
            $new_statuses['wc-reklamasjon'] = _x('Reklamasjon', 'Order status', 'woocommerce');
        }
    }
    if (!isset($new_statuses['wc-reklamasjon'])) {
        $new_statuses['wc-reklamasjon'] = _x('Reklamasjon', 'Order status', 'woocommerce');
    }
    return $new_statuses;
}

function np_order_hub_wpo_register_restordre_status() {
    register_post_status('wc-restordre', array(
        'label' => _x('Restordre', 'Order status', 'woocommerce'),
        'public' => true,
        'exclude_from_search' => false,
        'show_in_admin_status_list' => true,
        'show_in_admin_all_list' => true,
        'label_count' => _n_noop('Restordre <span class="count">(%s)</span>', 'Restordre <span class="count">(%s)</span>', 'woocommerce'),
    ));
}

function np_order_hub_wpo_add_restordre_status($statuses) {
    $new_statuses = array();
    foreach ((array) $statuses as $key => $label) {
        $new_statuses[$key] = $label;
        if ($key === 'wc-on-hold') {
            $new_statuses['wc-restordre'] = _x('Restordre', 'Order status', 'woocommerce');
        }
    }
    if (!isset($new_statuses['wc-restordre'])) {
        $new_statuses['wc-restordre'] = _x('Restordre', 'Order status', 'woocommerce');
    }
    return $new_statuses;
}

function np_order_hub_wpo_mark_restordre_for_hub($order_id, $old_status, $new_status, $order = null) {
    if ($new_status !== 'restordre') {
        return;
    }
    if (!$order && function_exists('wc_get_order')) {
        $order = wc_get_order($order_id);
    }
    if (!$order || !is_a($order, 'WC_Order')) {
        return;
    }
    if ($order->get_meta('_np_order_hub_force_send', true)) {
        return;
    }
    $order->update_meta_data('_np_order_hub_force_send', 'yes');
    $order->save();
}

function np_order_hub_wpo_order_is_editable($editable, $order) {
    if ($editable) {
        return $editable;
    }
    if (!$order || !is_a($order, 'WC_Order')) {
        return $editable;
    }
    $status = method_exists($order, 'get_status') ? (string) $order->get_status() : '';
    if ($status === 'reklamasjon' || $status === 'restordre' || $status === 'processing') {
        return true;
    }
    return $editable;
}

function np_order_hub_wpo_is_hub_disabled() {
    return (bool) get_option(NP_ORDER_HUB_WPO_DISABLE_HUB_OPTION, false);
}

function np_order_hub_wpo_set_hub_disabled($disabled) {
    update_option(NP_ORDER_HUB_WPO_DISABLE_HUB_OPTION, $disabled ? '1' : '0');
}

function np_order_hub_wpo_is_outgoing_email_disabled() {
    return (bool) get_option(NP_ORDER_HUB_WPO_DISABLE_EMAIL_OPTION, false);
}

function np_order_hub_wpo_set_outgoing_email_disabled($disabled) {
    update_option(NP_ORDER_HUB_WPO_DISABLE_EMAIL_OPTION, $disabled ? '1' : '0');
}

function np_order_hub_wpo_maybe_disable_outgoing_email($pre_wp_mail, $atts) {
    if (!np_order_hub_wpo_is_outgoing_email_disabled()) {
        return $pre_wp_mail;
    }
    if (is_array($atts)) {
        $to = '';
        if (!empty($atts['to'])) {
            if (is_array($atts['to'])) {
                $to = implode(', ', array_map('sanitize_text_field', $atts['to']));
            } else {
                $to = sanitize_text_field((string) $atts['to']);
            }
        }
        $subject = '';
        if (!empty($atts['subject'])) {
            $subject = sanitize_text_field((string) $atts['subject']);
        }
        np_order_hub_wpo_log('email_suppressed', array(
            'to' => $to,
            'subject' => $subject,
        ));
    } else {
        np_order_hub_wpo_log('email_suppressed');
    }
    return true;
}

function np_order_hub_wpo_is_hub_webhook($webhook) {
    $url = '';
    if (is_object($webhook) && method_exists($webhook, 'get_delivery_url')) {
        $url = (string) $webhook->get_delivery_url();
    } elseif (is_array($webhook) && !empty($webhook['delivery_url'])) {
        $url = (string) $webhook['delivery_url'];
    } elseif (is_object($webhook) && isset($webhook->delivery_url)) {
        $url = (string) $webhook->delivery_url;
    }
    if ($url === '') {
        return false;
    }
    if (strpos($url, '/wp-json/np-order-hub/v1/webhook') !== false) {
        return true;
    }
    return strpos($url, 'rest_route=/np-order-hub/v1/webhook') !== false;
}

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

function np_order_hub_wpo_push_new_order_to_hub($order_id) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'created', null);
}

function np_order_hub_wpo_push_order_status_change_to_hub($order_id, $old_status, $new_status, $order = null) {
    if ((string) $old_status === (string) $new_status) {
        return;
    }
    np_order_hub_wpo_push_order_to_hub($order_id, 'updated', $order);
}

function np_order_hub_wpo_push_order_update_to_hub($order_id, $order = null) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'updated', $order);
}

function np_order_hub_wpo_push_order_before_trash_to_hub($order_id, $order = null) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'deleted', $order);
}

function np_order_hub_wpo_push_order_trash_to_hub($order_id) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'deleted', null);
}

function np_order_hub_wpo_push_order_untrash_to_hub($order_id, $previous_status = '') {
    np_order_hub_wpo_push_order_to_hub($order_id, 'updated', null);
}

function np_order_hub_wpo_push_order_before_delete_to_hub($order_id, $order = null) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'deleted', $order);
}

function np_order_hub_wpo_push_order_delete_to_hub($order_id) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'deleted', null);
}

function np_order_hub_wpo_push_order_refunded_to_hub($order_id, $refund_id = 0) {
    np_order_hub_wpo_push_order_to_hub($order_id, 'updated', null);
}

function np_order_hub_wpo_push_order_refund_deleted_to_hub($refund_id, $order_id = 0) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return;
    }
    np_order_hub_wpo_push_order_to_hub($order_id, 'updated', null);
}

function np_order_hub_wpo_admin_menu() {
    add_submenu_page(
        'woocommerce',
        'Order Hub Packing Slip',
        'Order Hub Packing Slip',
        'manage_options',
        'np-order-hub-packing-slip',
        'np_order_hub_wpo_admin_page'
    );
}

function np_order_hub_wpo_admin_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (!empty($_POST['np_order_hub_wpo_save_settings']) && check_admin_referer('np_order_hub_wpo_save_settings')) {
        $disabled = !empty($_POST['np_order_hub_disable_hub']);
        $disable_email = !empty($_POST['np_order_hub_disable_email']);
        $delivery_bucket = np_order_hub_wpo_normalize_delivery_bucket((string) ($_POST['np_order_hub_delivery_bucket'] ?? 'standard'));
        if ($delivery_bucket === '') {
            $delivery_bucket = 'standard';
        }
        np_order_hub_wpo_set_hub_disabled($disabled);
        np_order_hub_wpo_set_outgoing_email_disabled($disable_email);
        update_option(NP_ORDER_HUB_WPO_DELIVERY_BUCKET_OPTION, $delivery_bucket);
        echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
    }

    if (!empty($_POST['np_order_hub_wpo_regen']) && check_admin_referer('np_order_hub_wpo_regen')) {
        $token = np_order_hub_wpo_generate_token();
        update_option(NP_ORDER_HUB_WPO_TOKEN_OPTION, $token);
        np_order_hub_wpo_log('token_regenerated', array('user_id' => get_current_user_id()));
        echo '<div class="notice notice-success"><p>Token regenerated.</p></div>';
    }

    $token = np_order_hub_wpo_get_token();
    $endpoint = rest_url('np-order-hub/v1/packing-slip');
    $bulk_endpoint = rest_url('np-order-hub/v1/packing-slips');
    $status_endpoint = rest_url('np-order-hub/v1/order-status');
    $hub_disabled = np_order_hub_wpo_is_hub_disabled();
    $email_disabled = np_order_hub_wpo_is_outgoing_email_disabled();
    $delivery_bucket = np_order_hub_wpo_get_default_delivery_bucket();

    echo '<div class="wrap">';
    echo '<h1>Order Hub Packing Slip</h1>';
    echo '<p>Use this token in the hub packing slip URL.</p>';
    echo '<table class="widefat striped" style="max-width: 800px;">';
    echo '<tbody>';
    echo '<tr><th style="width:180px;">Token</th><td><code>' . esc_html($token) . '</code></td></tr>';
    echo '<tr><th>Endpoint</th><td><code>' . esc_html($endpoint) . '</code></td></tr>';
    echo '<tr><th>Example</th><td><code>' . esc_html($endpoint . '?order_id={order_id}&token=' . $token) . '</code></td></tr>';
    echo '<tr><th>Bulk endpoint</th><td><code>' . esc_html($bulk_endpoint) . '</code></td></tr>';
    echo '<tr><th>Bulk example</th><td><code>' . esc_html($bulk_endpoint . '?order_ids=123,124&token=' . $token) . '</code></td></tr>';
    echo '<tr><th>Status endpoint</th><td><code>' . esc_html($status_endpoint) . '</code></td></tr>';
    echo '</tbody>';
    echo '</table>';
    echo '<form method="post" style="margin-top:16px;">';
    wp_nonce_field('np_order_hub_wpo_regen');
    echo '<button class="button" type="submit" name="np_order_hub_wpo_regen" value="1">Regenerate token</button>';
    echo '</form>';

    echo '<h2 style="margin-top:24px;">Order Hub Webhooks</h2>';
    if ($email_disabled) {
        echo '<div class="notice notice-warning inline"><p>Outgoing email is currently disabled for this store. Remember to re-enable it after migration/import is complete.</p></div>';
    }
    echo '<form method="post" style="margin-top:8px;">';
    wp_nonce_field('np_order_hub_wpo_save_settings');
    echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
    echo '<input type="checkbox" name="np_order_hub_disable_hub" value="1"' . checked($hub_disabled, true, false) . ' />';
    echo 'Disable sending orders to Order Hub';
    echo '</label>';
    echo '<p class="description" style="margin:6px 0 0;">When checked, webhooks to the Order Hub endpoint are skipped.</p>';
    echo '<label style="display:inline-flex; align-items:center; gap:6px; margin-top:10px;">';
    echo '<input type="checkbox" name="np_order_hub_disable_email" value="1"' . checked($email_disabled, true, false) . ' />';
    echo 'Disable all outgoing emails (use during order migration/import)';
    echo '</label>';
    echo '<p class="description" style="margin:6px 0 0;">When checked, WordPress email sending is suppressed for this store.</p>';
    echo '<table class="form-table" style="max-width:800px; margin-top:10px;">';
    echo '<tr><th scope="row"><label for="np-order-hub-delivery-bucket">Default delivery</label></th>';
    echo '<td><select name="np_order_hub_delivery_bucket" id="np-order-hub-delivery-bucket">';
    echo '<option value="standard"' . selected($delivery_bucket, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p class="description">All orders sent to the hub will be tagged with this delivery type.</p>';
    echo '</td></tr>';
    echo '</table>';
    echo '<p style="margin-top:10px;"><button class="button button-primary" type="submit" name="np_order_hub_wpo_save_settings" value="1">Save settings</button></p>';
    echo '</form>';
    echo '</div>';
}

function np_order_hub_wpo_add_reklamasjon_meta_box($post_type) {
    if ($post_type !== 'shop_order' || !current_user_can('edit_shop_orders')) {
        return;
    }
    add_meta_box(
        'np-order-hub-reklamasjon',
        'Reklamasjon',
        'np_order_hub_wpo_render_reklamasjon_meta_box',
        'shop_order',
        'normal',
        'default'
    );
}

function np_order_hub_wpo_add_reklamasjon_meta_box_hpos() {
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    add_meta_box(
        'np-order-hub-reklamasjon',
        'Reklamasjon',
        'np_order_hub_wpo_render_reklamasjon_meta_box',
        'woocommerce_page_wc-orders',
        'normal',
        'default'
    );
}

function np_order_hub_wpo_add_oos_meta_box($post_type) {
    if ($post_type !== 'shop_order' || !current_user_can('edit_shop_orders')) {
        return;
    }
    add_meta_box(
        'np-order-hub-oos',
        'Utsolgt',
        'np_order_hub_wpo_render_oos_meta_box',
        'shop_order',
        'normal',
        'default'
    );
}

function np_order_hub_wpo_add_oos_meta_box_hpos() {
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    add_meta_box(
        'np-order-hub-oos',
        'Utsolgt',
        'np_order_hub_wpo_render_oos_meta_box',
        'woocommerce_page_wc-orders',
        'normal',
        'default'
    );
}

function np_order_hub_wpo_get_order_from_meta_box($post) {
    if (is_object($post) && is_a($post, 'WC_Order')) {
        return $post;
    }
    if (is_object($post) && isset($post->ID)) {
        return wc_get_order((int) $post->ID);
    }
    if (is_numeric($post)) {
        return wc_get_order((int) $post);
    }
    return null;
}

function np_order_hub_wpo_get_item_stock_info($product, $qty) {
    $qty = (int) $qty;
    $managing_stock = $product && method_exists($product, 'managing_stock') && $product->managing_stock();
    $backorders = $product && method_exists($product, 'backorders_allowed') && $product->backorders_allowed();
    $in_stock = $product && method_exists($product, 'is_in_stock') ? $product->is_in_stock() : true;
    $stock_qty = null;
    if ($managing_stock && $product && method_exists($product, 'get_stock_quantity')) {
        $stock_qty = $product->get_stock_quantity();
        if ($stock_qty !== null) {
            $stock_qty = (int) $stock_qty;
        }
    }

    $out_of_stock = false;
    if ($managing_stock) {
        if (!$backorders) {
            $available = $stock_qty === null ? 0 : $stock_qty;
            if ($available < $qty) {
                $out_of_stock = true;
            }
        }
    } elseif (!$in_stock) {
        $out_of_stock = true;
    }

    $available_qty = 0;
    if ($managing_stock) {
        if ($backorders) {
            $available_qty = $qty;
        } else {
            $available_qty = $stock_qty === null ? 0 : (int) $stock_qty;
        }
    } else {
        $available_qty = $in_stock ? $qty : 0;
    }
    $missing_qty = $qty - $available_qty;
    if ($missing_qty < 0) {
        $missing_qty = 0;
    }
    if ($out_of_stock && $missing_qty < 1) {
        $missing_qty = $qty;
    }

    return array(
        'managing_stock' => $managing_stock,
        'backorders' => $backorders,
        'in_stock' => $in_stock,
        'stock_qty' => $stock_qty,
        'out_of_stock' => $out_of_stock,
        'missing_qty' => $missing_qty,
    );
}

function np_order_hub_wpo_render_reklamasjon_meta_box($post) {
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    $order = np_order_hub_wpo_get_order_from_meta_box($post);
    if (!$order) {
        echo '<p>Order not found.</p>';
        return;
    }
    $items = $order->get_items('line_item');
    if (empty($items)) {
        echo '<p>No line items found.</p>';
        return;
    }

    wp_nonce_field('np_order_hub_reklamasjon_create', 'np_order_hub_reklamasjon_nonce');
    echo '<input type="hidden" name="np_order_hub_reklamasjon_order_id" value="' . esc_attr((string) $order->get_id()) . '" />';
    echo '<p>Select items to create a claim order.</p>';
    echo '<table id="np-order-hub-reklamasjon-items" class="widefat striped" style="margin-top:8px;">';
    echo '<thead><tr>';
    echo '<th style="width:18px;"></th>';
    echo '<th>Product</th>';
    echo '<th>Qty</th>';
    echo '<th>Claim</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    foreach ($items as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }
        $product = $item->get_product();
        $name = $item->get_name();
        $qty = (int) $item->get_quantity();
        $sku = $product ? $product->get_sku() : '';
        $product_label = $name;
        if ($sku !== '') {
            $product_label .= ' (' . $sku . ')';
        }
        $managing_stock = $product && method_exists($product, 'managing_stock') && $product->managing_stock();
        $backorders = $product && method_exists($product, 'backorders_allowed') && $product->backorders_allowed();
        $in_stock = $product && method_exists($product, 'is_in_stock') ? $product->is_in_stock() : true;
        $stock_qty = '';
        if ($managing_stock && $product && method_exists($product, 'get_stock_quantity')) {
            $stock_value = $product->get_stock_quantity();
            if ($stock_value !== null) {
                $stock_qty = (string) $stock_value;
            }
        }

        echo '<tr data-product-label="' . esc_attr($product_label) . '" data-managing-stock="' . esc_attr($managing_stock ? '1' : '0') . '" data-backorders="' . esc_attr($backorders ? '1' : '0') . '" data-stock-qty="' . esc_attr($stock_qty) . '" data-in-stock="' . esc_attr($in_stock ? '1' : '0') . '">';
        echo '<td><input type="checkbox" name="np_order_hub_reklamasjon_items[]" value="' . esc_attr((string) $item_id) . '" /></td>';
        echo '<td>' . esc_html($name) . ($sku !== '' ? '<br /><span class="description">' . esc_html($sku) . '</span>' : '') . '</td>';
        echo '<td>' . esc_html((string) $qty) . '</td>';
        echo '<td><input type="number" name="np_order_hub_reklamasjon_qty[' . esc_attr((string) $item_id) . ']" min="0" max="' . esc_attr((string) $qty) . '" value="' . esc_attr((string) $qty) . '" style="width:70px;" /></td>';
        echo '</tr>';
    }
    echo '</tbody>';
    echo '</table>';
    echo '<p style="margin:10px 0 6px;">';
    echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
    echo '<input type="checkbox" name="np_order_hub_reklamasjon_allow_oos" value="1" /> Create even if out of stock (customer waiting for stock)';
    echo '</label>';
    echo '</p>';
    echo '<p style="margin-top:6px;">';
    echo '<button type="submit" class="button button-primary" name="np_order_hub_reklamasjon_create" value="1">Create claim order</button>';
    echo '</p>';
    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var button = document.querySelector("button[name=\'np_order_hub_reklamasjon_create\']");
            if (!button) {
                return;
            }
            button.addEventListener("click", function(event) {
                var allow = document.querySelector("input[name=\'np_order_hub_reklamasjon_allow_oos\']");
                if (allow && allow.checked) {
                    return;
                }
                var rows = document.querySelectorAll("#np-order-hub-reklamasjon-items tr[data-product-label]");
                var issues = [];
                rows.forEach(function(row) {
                    var checkbox = row.querySelector("input[name=\'np_order_hub_reklamasjon_items[]\']");
                    if (!checkbox || !checkbox.checked) {
                        return;
                    }
                    var qtyInput = row.querySelector("input[name^=\'np_order_hub_reklamasjon_qty\']");
                    var qty = qtyInput ? parseInt(qtyInput.value, 10) : 0;
                    if (!qty || qty < 1) {
                        return;
                    }
                    var managing = row.getAttribute("data-managing-stock") === "1";
                    var backorders = row.getAttribute("data-backorders") === "1";
                    var inStock = row.getAttribute("data-in-stock") === "1";
                    var stockRaw = row.getAttribute("data-stock-qty");
                    var stockQty = stockRaw === "" ? null : parseInt(stockRaw, 10);
                    var out = false;
                    if (managing) {
                        if (!backorders) {
                            if (stockQty === null || qty > stockQty) {
                                out = true;
                            }
                        }
                    } else if (!inStock) {
                        out = true;
                    }
                    if (out) {
                        issues.push(row.getAttribute("data-product-label") || "Product");
                    }
                });
                if (!issues.length) {
                    return;
                }
                var message = issues.length === 1
                    ? "Produktet er utsolgt. Opprette reklamasjon og sette som restordre?"
                    : "Produkter er utsolgt. Opprette reklamasjon og sette som restordre?";
                if (window.confirm(message)) {
                    if (allow) {
                        allow.checked = true;
                    }
                } else {
                    event.preventDefault();
                    event.stopPropagation();
                }
            });
        });
    </script>';
}

function np_order_hub_wpo_render_oos_meta_box($post) {
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    $order = np_order_hub_wpo_get_order_from_meta_box($post);
    if (!$order) {
        echo '<p>Order not found.</p>';
        return;
    }
    $items = $order->get_items('line_item');
    if (empty($items)) {
        echo '<p>No line items found.</p>';
        return;
    }

    $has_oos = false;
    wp_nonce_field('np_order_hub_oos_create', 'np_order_hub_oos_nonce');
    echo '<input type="hidden" name="np_order_hub_oos_order_id" value="' . esc_attr((string) $order->get_id()) . '" />';
    echo '<p>Flytt utsolgte varer til en ny restordre og fjern dem fra denne ordren.</p>';
    echo '<table id="np-order-hub-oos-items" class="widefat striped" style="margin-top:8px;">';
    echo '<thead><tr>';
    echo '<th style="width:18px;"></th>';
    echo '<th>Product</th>';
    echo '<th>Qty</th>';
    echo '<th>Flytt</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    foreach ($items as $item_id => $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }
        $product = $item->get_product();
        $name = $item->get_name();
        $qty = (int) $item->get_quantity();
        $sku = $product ? $product->get_sku() : '';
        $product_label = $name;
        if ($sku !== '') {
            $product_label .= ' (' . $sku . ')';
        }
        $stock_info = np_order_hub_wpo_get_item_stock_info($product, $qty);
        $missing_qty = isset($stock_info['missing_qty']) ? (int) $stock_info['missing_qty'] : 0;
        $is_oos = !empty($stock_info['out_of_stock']) && $missing_qty > 0;
        $checked = $is_oos ? ' checked' : '';
        if ($is_oos) {
            $has_oos = true;
        }
        $default_qty = $missing_qty > 0 ? $missing_qty : $qty;

        echo '<tr data-product-label="' . esc_attr($product_label) . '" data-out-of-stock="' . esc_attr($is_oos ? '1' : '0') . '" data-missing="' . esc_attr((string) $missing_qty) . '">';
        echo '<td><input type="checkbox" name="np_order_hub_oos_items[]" value="' . esc_attr((string) $item_id) . '"' . $checked . ' /></td>';
        echo '<td>' . esc_html($name) . ($sku !== '' ? '<br /><span class="description">' . esc_html($sku) . '</span>' : '') . '</td>';
        echo '<td>' . esc_html((string) $qty) . '</td>';
        echo '<td><input type="number" name="np_order_hub_oos_qty[' . esc_attr((string) $item_id) . ']" min="0" max="' . esc_attr((string) $qty) . '" value="' . esc_attr((string) $default_qty) . '" style="width:70px;" /></td>';
        echo '</tr>';
    }
    echo '</tbody>';
    echo '</table>';
    if (!$has_oos) {
        echo '<p style="margin:8px 0 0;"><em>Ingen utsolgte varer funnet.</em></p>';
    } else {
        echo '<p style="margin:8px 0 0;">Antall er forhåndsutfylt med manglende lager basert på lagerstatus.</p>';
    }
    echo '<p style="margin-top:8px;">';
    echo '<button type="submit" class="button button-primary" name="np_order_hub_oos_create" value="1"' . ($has_oos ? '' : ' disabled') . '>Opprett restordre for utsolgte</button>';
    echo '</p>';
}

function np_order_hub_wpo_get_order_edit_url($order) {
    if (!$order || !is_object($order)) {
        return admin_url('edit.php?post_type=shop_order');
    }
    if (method_exists($order, 'get_edit_order_url')) {
        $url = (string) $order->get_edit_order_url();
        if ($url !== '') {
            return $url;
        }
    }
    $order_id = method_exists($order, 'get_id') ? (int) $order->get_id() : 0;
    if ($order_id > 0) {
        $url = get_edit_post_link($order_id, '');
        if (is_string($url) && $url !== '') {
            return $url;
        }
        return admin_url('post.php?post=' . $order_id . '&action=edit');
    }
    return admin_url('edit.php?post_type=shop_order');
}

function np_order_hub_wpo_handle_reklamasjon_create() {
    if (empty($_POST['np_order_hub_reklamasjon_create'])) {
        return;
    }
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    if (!isset($_POST['np_order_hub_reklamasjon_nonce']) || !wp_verify_nonce((string) $_POST['np_order_hub_reklamasjon_nonce'], 'np_order_hub_reklamasjon_create')) {
        return;
    }
    if (!function_exists('wc_get_order')) {
        return;
    }

    $order_id = isset($_POST['np_order_hub_reklamasjon_order_id']) ? absint($_POST['np_order_hub_reklamasjon_order_id']) : 0;
    if ($order_id < 1 && !empty($_POST['post_ID'])) {
        $order_id = absint($_POST['post_ID']);
    }
    $order = $order_id > 0 ? wc_get_order($order_id) : null;
    if (!$order) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_reklamasjon_notice' => 'error',
                'np_order_hub_reklamasjon_message' => 'Order not found.',
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $selected_items = isset($_POST['np_order_hub_reklamasjon_items']) ? array_map('absint', (array) $_POST['np_order_hub_reklamasjon_items']) : array();
    $qty_input = isset($_POST['np_order_hub_reklamasjon_qty']) && is_array($_POST['np_order_hub_reklamasjon_qty']) ? $_POST['np_order_hub_reklamasjon_qty'] : array();
    $allow_oos = !empty($_POST['np_order_hub_reklamasjon_allow_oos']);
    $selected = array();
    foreach ($selected_items as $item_id) {
        $qty = isset($qty_input[$item_id]) ? absint($qty_input[$item_id]) : 0;
        if ($item_id > 0 && $qty > 0) {
            $selected[$item_id] = $qty;
        }
    }

    if (empty($selected)) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_reklamasjon_notice' => 'error',
                'np_order_hub_reklamasjon_message' => 'Select at least one item.',
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $new_order = np_order_hub_wpo_create_reklamasjon_order_from_order($order, $selected, $allow_oos);
    if (is_wp_error($new_order)) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_reklamasjon_notice' => 'error',
                'np_order_hub_reklamasjon_message' => $new_order->get_error_message(),
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $redirect = add_query_arg(
        array(
            'np_order_hub_reklamasjon_notice' => 'success',
            'np_order_hub_reklamasjon_new' => $new_order->get_id(),
        ),
        np_order_hub_wpo_get_order_edit_url($order)
    );
    wp_safe_redirect($redirect);
    exit;
}

function np_order_hub_wpo_handle_oos_create() {
    if (empty($_POST['np_order_hub_oos_create'])) {
        return;
    }
    if (!current_user_can('edit_shop_orders')) {
        return;
    }
    if (!isset($_POST['np_order_hub_oos_nonce']) || !wp_verify_nonce((string) $_POST['np_order_hub_oos_nonce'], 'np_order_hub_oos_create')) {
        return;
    }
    if (!function_exists('wc_get_order')) {
        return;
    }

    $order_id = isset($_POST['np_order_hub_oos_order_id']) ? absint($_POST['np_order_hub_oos_order_id']) : 0;
    if ($order_id < 1 && !empty($_POST['post_ID'])) {
        $order_id = absint($_POST['post_ID']);
    }
    $order = $order_id > 0 ? wc_get_order($order_id) : null;
    if (!$order) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_oos_notice' => 'error',
                'np_order_hub_oos_message' => 'Order not found.',
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $selected_items = isset($_POST['np_order_hub_oos_items']) ? array_map('absint', (array) $_POST['np_order_hub_oos_items']) : array();
    $qty_input = isset($_POST['np_order_hub_oos_qty']) && is_array($_POST['np_order_hub_oos_qty']) ? $_POST['np_order_hub_oos_qty'] : array();
    $selected = array();
    $errors = array();

    foreach ($selected_items as $item_id) {
        $qty = isset($qty_input[$item_id]) ? absint($qty_input[$item_id]) : 0;
        if ($item_id < 1 || $qty < 1) {
            continue;
        }
        $order_item = $order->get_item($item_id);
        if (!$order_item || !is_a($order_item, 'WC_Order_Item_Product')) {
            $errors[] = 'Item not found.';
            continue;
        }
        $max_qty = (int) $order_item->get_quantity();
        if ($max_qty < 1 || $qty > $max_qty) {
            $errors[] = 'Invalid quantity selected.';
            continue;
        }
        $product = $order_item->get_product();
        if (!$product) {
            $errors[] = 'Product not found.';
            continue;
        }
        $stock_info = np_order_hub_wpo_get_item_stock_info($product, $max_qty);
        $missing_qty = isset($stock_info['missing_qty']) ? (int) $stock_info['missing_qty'] : 0;
        if ($missing_qty < 1) {
            $errors[] = 'Selected items are not out of stock.';
            continue;
        }
        if ($qty > $missing_qty) {
            $errors[] = 'Selected quantity exceeds out-of-stock amount.';
            continue;
        }
        $selected[$item_id] = $qty;
    }

    if (empty($selected) && empty($errors)) {
        $errors[] = 'Select at least one out-of-stock item.';
    }

    if (!empty($errors)) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_oos_notice' => 'error',
                'np_order_hub_oos_message' => $errors[0],
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $new_order = np_order_hub_wpo_create_restordre_order_from_order($order, $selected);
    if (is_wp_error($new_order)) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_oos_notice' => 'error',
                'np_order_hub_oos_message' => $new_order->get_error_message(),
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $split_result = np_order_hub_wpo_apply_oos_split_to_order($order, $selected, $new_order);
    if (is_wp_error($split_result)) {
        $redirect = add_query_arg(
            array(
                'np_order_hub_oos_notice' => 'error',
                'np_order_hub_oos_message' => $split_result->get_error_message(),
                'np_order_hub_oos_new' => $new_order->get_id(),
            ),
            np_order_hub_wpo_get_order_edit_url($order)
        );
        wp_safe_redirect($redirect);
        exit;
    }

    $redirect = add_query_arg(
        array(
            'np_order_hub_oos_notice' => 'success',
            'np_order_hub_oos_new' => $new_order->get_id(),
        ),
        np_order_hub_wpo_get_order_edit_url($order)
    );
    wp_safe_redirect($redirect);
    exit;
}

function np_order_hub_wpo_reklamasjon_admin_notice() {
    if (empty($_GET['np_order_hub_reklamasjon_notice'])) {
        return;
    }
    $type = sanitize_key((string) $_GET['np_order_hub_reklamasjon_notice']);
    $message = isset($_GET['np_order_hub_reklamasjon_message']) ? sanitize_text_field((string) $_GET['np_order_hub_reklamasjon_message']) : '';
    if ($type === 'success') {
        $new_id = isset($_GET['np_order_hub_reklamasjon_new']) ? absint($_GET['np_order_hub_reklamasjon_new']) : 0;
        $link = '';
        if ($new_id > 0 && function_exists('wc_get_order')) {
            $new_order = wc_get_order($new_id);
            if ($new_order) {
                $label = method_exists($new_order, 'get_order_number') ? (string) $new_order->get_order_number() : (string) $new_id;
                $url = np_order_hub_wpo_get_order_edit_url($new_order);
                if ($url !== '') {
                    $link = '<a href="' . esc_url($url) . '">#' . esc_html($label) . '</a>';
                } else {
                    $link = '#' . esc_html($label);
                }
            }
        }
        $notice = $link !== '' ? ('Claim order created: ' . $link . '.') : 'Claim order created.';
        echo '<div class="notice notice-success"><p>' . wp_kses_post($notice) . '</p></div>';
        return;
    }
    if ($message === '') {
        $message = 'Failed to create claim order.';
    }
    echo '<div class="notice notice-error"><p>' . esc_html($message) . '</p></div>';
}

function np_order_hub_wpo_oos_admin_notice() {
    if (empty($_GET['np_order_hub_oos_notice'])) {
        return;
    }
    $type = sanitize_key((string) $_GET['np_order_hub_oos_notice']);
    $message = isset($_GET['np_order_hub_oos_message']) ? sanitize_text_field((string) $_GET['np_order_hub_oos_message']) : '';
    if ($type === 'success') {
        $new_id = isset($_GET['np_order_hub_oos_new']) ? absint($_GET['np_order_hub_oos_new']) : 0;
        $link = '';
        if ($new_id > 0 && function_exists('wc_get_order')) {
            $new_order = wc_get_order($new_id);
            if ($new_order) {
                $label = method_exists($new_order, 'get_order_number') ? (string) $new_order->get_order_number() : (string) $new_id;
                $url = np_order_hub_wpo_get_order_edit_url($new_order);
                if ($url !== '') {
                    $link = '<a href="' . esc_url($url) . '">#' . esc_html($label) . '</a>';
                } else {
                    $link = '#' . esc_html($label);
                }
            }
        }
        $notice = $link !== '' ? ('Restordre created: ' . $link . '.') : 'Restordre created.';
        echo '<div class="notice notice-success"><p>' . wp_kses_post($notice) . '</p></div>';
        return;
    }
    if ($message === '') {
        $message = 'Failed to create restordre.';
    }
    echo '<div class="notice notice-error"><p>' . esc_html($message) . '</p></div>';
}

function np_order_hub_wpo_register_routes() {
    register_rest_route('np-order-hub/v1', '/packing-slip', array(
        'methods' => 'GET',
        'callback' => 'np_order_hub_wpo_packing_slip',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/packing-slips', array(
        'methods' => 'GET',
        'callback' => 'np_order_hub_wpo_packing_slips',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/order-status', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_wpo_update_order_status',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/reklamasjon-order', array(
        'methods' => 'POST',
        'callback' => 'np_order_hub_wpo_create_reklamasjon_order',
        'permission_callback' => '__return_true',
    ));
}

function np_order_hub_wpo_packing_slip(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('packing_slip_request', array(
        'order_id' => $order_id,
        'token_present' => $token !== '',
        'ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        np_order_hub_wpo_log('packing_slip_unauthorized', array('order_id' => $order_id));
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1) {
        return new WP_REST_Response(array('error' => 'missing_order_id'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }
    $order = wc_get_order($order_id);
    if (!$order) {
        return new WP_REST_Response(array('error' => 'order_not_found'), 404);
    }
    $document = np_order_hub_get_wpo_document($order);
    if (!$document || is_wp_error($document)) {
        np_order_hub_wpo_log('packing_slip_document_missing', array(
            'order_id' => $order_id,
            'is_error' => is_wp_error($document),
        ));
        return new WP_REST_Response(array('error' => 'document_missing'), 500);
    }

    nocache_headers();
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="packing-slip-' . $order_id . '.pdf"');

    if (method_exists($document, 'output_pdf')) {
        $document->output_pdf();
        exit;
    }
    if (method_exists($document, 'get_pdf')) {
        $pdf = $document->get_pdf();
        if (!empty($pdf)) {
            echo $pdf;
            exit;
        }
    }

    return new WP_REST_Response(array('error' => 'pdf_output_failed'), 500);
}

function np_order_hub_wpo_parse_order_ids($raw) {
    if (is_array($raw)) {
        $ids = array_map('absint', $raw);
    } else {
        $raw = (string) $raw;
        $ids = $raw !== '' ? array_map('absint', explode(',', $raw)) : array();
    }
    $ids = array_filter($ids, function ($value) {
        return $value > 0;
    });
    return array_values(array_unique($ids));
}

function np_order_hub_wpo_get_pdf_bytes($document) {
    if (is_object($document) && method_exists($document, 'get_pdf')) {
        $pdf = $document->get_pdf();
        if (!empty($pdf)) {
            return $pdf;
        }
    }
    if (is_object($document) && method_exists($document, 'output_pdf')) {
        ob_start();
        $document->output_pdf();
        $pdf = ob_get_clean();
        if (!empty($pdf)) {
            return $pdf;
        }
    }
    return '';
}

function np_order_hub_wpo_try_bulk_document($orders, $order_ids) {
    if (!function_exists('wcpdf_get_document')) {
        return null;
    }
    $candidates = array(
        array('label' => 'orders', 'value' => $orders),
        array('label' => 'order_ids', 'value' => $order_ids),
    );
    foreach ($candidates as $candidate) {
        if (empty($candidate['value'])) {
            continue;
        }
        try {
            $document = wcpdf_get_document('packing-slip', $candidate['value']);
            if (is_wp_error($document)) {
                np_order_hub_wpo_log('bulk_document_error', array(
                    'input' => $candidate['label'],
                    'code' => $document->get_error_code(),
                    'message' => $document->get_error_message(),
                ));
                continue;
            }
            if ($document) {
                np_order_hub_wpo_log('bulk_document_ok', array('input' => $candidate['label']));
                return $document;
            }
        } catch (Throwable $e) {
            np_order_hub_wpo_log('bulk_document_error', array(
                'input' => $candidate['label'],
                'message' => $e->getMessage(),
            ));
        }
    }
    return null;
}

function np_order_hub_wpo_merge_pdfs($pdf_paths) {
    if (empty($pdf_paths)) {
        return new WP_Error('empty_pdfs', 'No PDFs to merge.');
    }
    $qpdf = function_exists('shell_exec') ? trim((string) shell_exec('command -v qpdf 2>/dev/null')) : '';
    if ($qpdf) {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellcmd($qpdf) . ' --empty --pages';
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' -- ' . escapeshellarg($out) . ' 2>/dev/null';
            @shell_exec($cmd);
            if (is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (is_file($out)) {
                @unlink($out);
            }
        }
    }

    $gs = function_exists('shell_exec') ? trim((string) shell_exec('command -v gs 2>/dev/null')) : '';
    if ($gs) {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellcmd($gs) . ' -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=' . escapeshellarg($out);
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' 2>/dev/null';
            @shell_exec($cmd);
            if (is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (is_file($out)) {
                @unlink($out);
            }
        }
    }

    return new WP_Error('merge_unavailable', 'Could not merge PDFs on this server.');
}

function np_order_hub_wpo_packing_slips(WP_REST_Request $request) {
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }
    if (!np_order_hub_wpo_check_token($token)) {
        np_order_hub_wpo_log('packing_slips_unauthorized');
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }
    $order_ids = np_order_hub_wpo_parse_order_ids($request->get_param('order_ids'));
    if (empty($order_ids)) {
        return new WP_REST_Response(array('error' => 'missing_order_ids'), 400);
    }

    $orders = array();
    foreach ($order_ids as $order_id) {
        $order = wc_get_order($order_id);
        if ($order) {
            $orders[] = $order;
        }
    }
    if (empty($orders)) {
        return new WP_REST_Response(array('error' => 'orders_not_found'), 404);
    }

    $bulk_document = np_order_hub_wpo_try_bulk_document($orders, $order_ids);
    if ($bulk_document) {
        $bulk_pdf = np_order_hub_wpo_get_pdf_bytes($bulk_document);
        if ($bulk_pdf !== '') {
            nocache_headers();
            header('Content-Type: application/pdf');
            header('Content-Disposition: inline; filename="packing-slips-' . gmdate('Ymd-His') . '.pdf"');
            echo $bulk_pdf;
            exit;
        }
    }

    $pdf_paths = array();
    foreach ($orders as $order) {
        $document = np_order_hub_get_wpo_document($order);
        if (!$document || is_wp_error($document)) {
            np_order_hub_wpo_log('packing_slips_document_missing', array(
                'order_id' => $order->get_id(),
            ));
            continue;
        }
        $pdf_bytes = np_order_hub_wpo_get_pdf_bytes($document);
        if ($pdf_bytes === '') {
            np_order_hub_wpo_log('packing_slips_pdf_empty', array(
                'order_id' => $order->get_id(),
            ));
            continue;
        }
        $tmp = wp_tempnam('packing-slip-' . $order->get_id());
        if ($tmp) {
            $path = $tmp . '.pdf';
            @rename($tmp, $path);
            file_put_contents($path, $pdf_bytes);
            $pdf_paths[] = $path;
        }
    }

    $merged = np_order_hub_wpo_merge_pdfs($pdf_paths);
    foreach ($pdf_paths as $path) {
        if (is_file($path)) {
            @unlink($path);
        }
    }

    if (is_wp_error($merged)) {
        np_order_hub_wpo_log('packing_slips_merge_failed', array(
            'code' => $merged->get_error_code(),
            'message' => $merged->get_error_message(),
        ));
        return new WP_REST_Response(array('error' => $merged->get_error_message()), 500);
    }

    if (!is_file($merged)) {
        return new WP_REST_Response(array('error' => 'merge_failed'), 500);
    }

    nocache_headers();
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="packing-slips-' . gmdate('Ymd-His') . '.pdf"');
    readfile($merged);
    @unlink($merged);
    exit;
}

function np_order_hub_wpo_update_order_status(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $status = sanitize_key((string) $request->get_param('status'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('status_update_request', array(
        'order_id' => $order_id,
        'status' => $status,
        'token_present' => $token !== '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1 || $status === '') {
        return new WP_REST_Response(array('error' => 'missing_params'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }
    $order = wc_get_order($order_id);
    if (!$order) {
        return new WP_REST_Response(array('error' => 'order_not_found'), 404);
    }
    $allowed = array('pending', 'processing', 'restordre', 'completed', 'on-hold', 'cancelled', 'refunded', 'reklamasjon', 'failed');
    if (!in_array($status, $allowed, true)) {
        return new WP_REST_Response(array('error' => 'invalid_status'), 400);
    }
    $order->update_status($status, 'Updated from Order Hub', true);
    return new WP_REST_Response(array(
        'status' => 'ok',
        'order_id' => $order_id,
        'new_status' => $status,
    ), 200);
}

function np_order_hub_wpo_get_request_params(WP_REST_Request $request) {
    $params = $request->get_json_params();
    if (!is_array($params) || empty($params)) {
        $params = $request->get_params();
    }
    return is_array($params) ? $params : array();
}

function np_order_hub_wpo_scale_taxes($taxes, $ratio, $precision) {
    if (!is_array($taxes) || $ratio === 1.0) {
        return $taxes;
    }
    $scaled = $taxes;
    foreach (array('total', 'subtotal') as $key) {
        if (empty($scaled[$key]) || !is_array($scaled[$key])) {
            continue;
        }
        foreach ($scaled[$key] as $rate_id => $amount) {
            $scaled[$key][$rate_id] = round(((float) $amount) * $ratio, $precision);
        }
    }
    return $scaled;
}

function np_order_hub_wpo_reduce_reklamasjon_stock($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return;
    }
    $order_id = $order->get_id();
    if ($order_id < 1) {
        return;
    }
    $stock_reduced = $order->get_meta('_order_stock_reduced', true);
    if ($stock_reduced) {
        return;
    }

    if (function_exists('wc_reduce_stock_levels')) {
        wc_reduce_stock_levels($order_id);
    }

    $fresh = function_exists('wc_get_order') ? wc_get_order($order_id) : $order;
    if ($fresh && $fresh->get_meta('_order_stock_reduced', true)) {
        return;
    }

    if (!function_exists('wc_update_product_stock')) {
        return;
    }

    $changes = array();
    foreach ($order->get_items('line_item') as $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }
        $product = $item->get_product();
        if (!$product || !method_exists($product, 'managing_stock') || !$product->managing_stock()) {
            continue;
        }
        $qty = method_exists($item, 'get_quantity') ? (int) $item->get_quantity() : 0;
        if ($qty < 1) {
            continue;
        }
        if (function_exists('wc_stock_amount')) {
            $qty = wc_stock_amount($qty);
        }
        $old_stock = method_exists($product, 'get_stock_quantity') ? $product->get_stock_quantity() : null;
        $new_stock = wc_update_product_stock($product, $qty, 'decrease');
        if (!is_wp_error($new_stock)) {
            $label = method_exists($product, 'get_name') ? $product->get_name() : 'Product';
            if ($old_stock !== null) {
                $changes[] = $label . ' ' . $old_stock . '→' . $new_stock;
            } else {
                $changes[] = $label . ' -' . $qty;
            }
        }
    }

    if (!empty($changes)) {
        $order->update_meta_data('_order_stock_reduced', 'yes');
        $order->update_meta_data('_np_reklamasjon_stock_reduced', 'yes');
        $order->add_order_note('Stock reduced (reklamasjon): ' . implode(', ', $changes));
        $order->save();
    }
}

function np_order_hub_wpo_get_stock_issues($prepared_items) {
    $issues = array();
    foreach ((array) $prepared_items as $prepared) {
        if (empty($prepared['product']) || empty($prepared['quantity'])) {
            continue;
        }
        $product = $prepared['product'];
        if (!is_object($product)) {
            continue;
        }
        $qty = (int) $prepared['quantity'];
        if (method_exists($product, 'managing_stock') && $product->managing_stock()) {
            if (method_exists($product, 'backorders_allowed') && $product->backorders_allowed()) {
                continue;
            }
            $stock = method_exists($product, 'get_stock_quantity') ? $product->get_stock_quantity() : null;
            if ($stock === null) {
                $stock = 0;
            }
            if ($stock < $qty) {
                $label = method_exists($product, 'get_name') ? $product->get_name() : 'Product';
                $sku = method_exists($product, 'get_sku') ? $product->get_sku() : '';
                if (is_string($sku) && $sku !== '') {
                    $label .= ' (' . $sku . ')';
                }
                $issues[] = array(
                    'label' => $label,
                    'requested' => $qty,
                    'available' => (int) $stock,
                );
            }
            continue;
        }

        if (method_exists($product, 'is_in_stock') && !$product->is_in_stock()) {
            $label = method_exists($product, 'get_name') ? $product->get_name() : 'Product';
            $sku = method_exists($product, 'get_sku') ? $product->get_sku() : '';
            if (is_string($sku) && $sku !== '') {
                $label .= ' (' . $sku . ')';
            }
            $issues[] = array(
                'label' => $label,
                'requested' => $qty,
                'available' => 0,
            );
        }
    }
    return $issues;
}

function np_order_hub_wpo_format_stock_issues($issues) {
    $lines = array();
    foreach ((array) $issues as $issue) {
        if (empty($issue['label'])) {
            continue;
        }
        $requested = isset($issue['requested']) ? (int) $issue['requested'] : 0;
        $available = isset($issue['available']) ? (int) $issue['available'] : 0;
        $lines[] = $issue['label'] . ' (' . $requested . '/' . $available . ')';
    }
    return implode(', ', $lines);
}

function np_order_hub_wpo_normalize_reklamasjon_items($items) {
    $selected = array();
    if (!is_array($items)) {
        return $selected;
    }
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }
        $item_id = isset($item['item_id']) ? absint($item['item_id']) : (isset($item['id']) ? absint($item['id']) : 0);
        $qty = isset($item['quantity']) ? absint($item['quantity']) : 0;
        if ($item_id < 1 || $qty < 1) {
            continue;
        }
        if (isset($selected[$item_id])) {
            $selected[$item_id] += $qty;
        } else {
            $selected[$item_id] = $qty;
        }
    }
    return $selected;
}

function np_order_hub_wpo_prepare_reklamasjon_items($order, $selected) {
    if (!$order || !is_object($order)) {
        return new WP_Error('order_not_found', 'Order not found.');
    }
    if (empty($selected) || !is_array($selected)) {
        return new WP_Error('missing_items', 'Missing items.');
    }

    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;
    $prepared_items = array();
    foreach ($selected as $item_id => $qty) {
        $order_item = $order->get_item($item_id);
        if (!$order_item || !is_a($order_item, 'WC_Order_Item_Product')) {
            return new WP_Error('item_not_found', 'Item not found.');
        }
        $max_qty = (int) $order_item->get_quantity();
        if ($max_qty < 1 || $qty > $max_qty) {
            return new WP_Error('invalid_quantity', 'Invalid quantity.');
        }
        $product = $order_item->get_product();
        if (!$product) {
            return new WP_Error('product_not_found', 'Product not found.');
        }

        $ratio = $max_qty > 0 ? ($qty / $max_qty) : 1;
        $subtotal = (float) $order_item->get_subtotal();
        $total = (float) $order_item->get_total();
        $subtotal_tax = (float) $order_item->get_subtotal_tax();
        $total_tax = (float) $order_item->get_total_tax();
        $taxes = $order_item->get_taxes();

        if ($ratio !== 1.0) {
            $subtotal = round($subtotal * $ratio, $precision);
            $total = round($total * $ratio, $precision);
            $subtotal_tax = round($subtotal_tax * $ratio, $precision);
            $total_tax = round($total_tax * $ratio, $precision);
            $taxes = np_order_hub_wpo_scale_taxes($taxes, $ratio, $precision);
        }

        $prepared_items[] = array(
            'item' => $order_item,
            'product' => $product,
            'quantity' => $qty,
            'subtotal' => $subtotal,
            'total' => $total,
            'subtotal_tax' => $subtotal_tax,
            'total_tax' => $total_tax,
            'taxes' => $taxes,
        );
    }

    if (empty($prepared_items)) {
        return new WP_Error('missing_items', 'Missing items.');
    }

    return $prepared_items;
}

function np_order_hub_wpo_create_reklamasjon_order_from_order($order, $selected, $allow_oos = false) {
    if (!function_exists('wc_create_order')) {
        return new WP_Error('woocommerce_missing', 'WooCommerce missing.');
    }
    $prepared_items = np_order_hub_wpo_prepare_reklamasjon_items($order, $selected);
    if (is_wp_error($prepared_items)) {
        return $prepared_items;
    }
    $stock_issues = np_order_hub_wpo_get_stock_issues($prepared_items);
    $waiting_note = '';
    $status = 'reklamasjon';
    if (!empty($stock_issues)) {
        $issue_list = np_order_hub_wpo_format_stock_issues($stock_issues);
        if (!$allow_oos) {
            $message = 'Some items are out of stock: ' . $issue_list . '. Remove the items or allow creation and mark as restordre.';
            return new WP_Error('stock_unavailable', $message);
        }
        $status = 'restordre';
        $waiting_note = 'Restordre: customer waiting for stock: ' . $issue_list . '.';
    }

    $new_order = wc_create_order(array(
        'customer_id' => $order->get_customer_id(),
        'status' => $status,
    ));
    if (is_wp_error($new_order)) {
        return $new_order;
    }
    if (!$new_order || !is_a($new_order, 'WC_Order')) {
        return new WP_Error('order_create_failed', 'Order creation failed.');
    }

    $order_id = method_exists($order, 'get_id') ? (int) $order->get_id() : 0;
    $new_order->set_created_via('np-order-hub');
    $new_order->set_currency($order->get_currency());
    $new_order->set_address($order->get_address('billing'), 'billing');
    $new_order->set_address($order->get_address('shipping'), 'shipping');
    if ($order_id > 0) {
        $new_order->update_meta_data('_np_reklamasjon_source_order', $order_id);
    }

    $skip_meta_keys = array(
        '_product_id',
        '_variation_id',
        '_qty',
        '_tax_class',
        '_line_subtotal',
        '_line_subtotal_tax',
        '_line_total',
        '_line_tax',
        '_line_tax_data',
    );

    foreach ($prepared_items as $prepared) {
        $order_item = $prepared['item'];
        $new_item = new WC_Order_Item_Product();
        $new_item->set_product($prepared['product']);
        $new_item->set_quantity($prepared['quantity']);
        $new_item->set_subtotal($prepared['subtotal']);
        $new_item->set_total($prepared['total']);
        $new_item->set_subtotal_tax($prepared['subtotal_tax']);
        $new_item->set_total_tax($prepared['total_tax']);
        if (is_array($prepared['taxes'])) {
            $new_item->set_taxes($prepared['taxes']);
        }
        $variation_id = method_exists($order_item, 'get_variation_id') ? (int) $order_item->get_variation_id() : 0;
        if ($variation_id > 0) {
            $new_item->set_variation_id($variation_id);
        }
        $new_item->set_name($order_item->get_name());

        $meta_data = $order_item->get_meta_data();
        foreach ($meta_data as $meta) {
            $data = $meta->get_data();
            $key = isset($data['key']) ? (string) $data['key'] : '';
            if ($key === '' || in_array($key, $skip_meta_keys, true)) {
                continue;
            }
            $new_item->add_meta_data($key, $data['value'], true);
        }

        $new_order->add_item($new_item);
    }

    if ($order_id > 0) {
        $new_order->add_order_note('Claim order created from order #' . $order_id . ' via Order Hub.');
    } else {
        $new_order->add_order_note('Claim order created via Order Hub.');
    }
    if ($waiting_note !== '') {
        $new_order->add_order_note($waiting_note);
        $new_order->update_meta_data('_np_reklamasjon_waiting_stock', 'yes');
    }
    $new_order->calculate_totals(false);
    $new_order->save();

    np_order_hub_wpo_reduce_reklamasjon_stock($new_order);

    return $new_order;
}

function np_order_hub_wpo_create_restordre_order_from_order($order, $selected) {
    if (!function_exists('wc_create_order')) {
        return new WP_Error('woocommerce_missing', 'WooCommerce missing.');
    }
    $prepared_items = np_order_hub_wpo_prepare_reklamasjon_items($order, $selected);
    if (is_wp_error($prepared_items)) {
        return $prepared_items;
    }

    $new_order = wc_create_order(array(
        'customer_id' => $order->get_customer_id(),
        'status' => 'restordre',
    ));
    if (is_wp_error($new_order)) {
        return $new_order;
    }
    if (!$new_order || !is_a($new_order, 'WC_Order')) {
        return new WP_Error('order_create_failed', 'Order creation failed.');
    }

    $order_id = method_exists($order, 'get_id') ? (int) $order->get_id() : 0;
    $new_order->set_created_via('np-order-hub');
    $new_order->set_currency($order->get_currency());
    $new_order->set_address($order->get_address('billing'), 'billing');
    $new_order->set_address($order->get_address('shipping'), 'shipping');
    if ($order_id > 0) {
        $new_order->update_meta_data('_np_restordre_source_order', $order_id);
    }

    $skip_meta_keys = array(
        '_product_id',
        '_variation_id',
        '_qty',
        '_tax_class',
        '_line_subtotal',
        '_line_subtotal_tax',
        '_line_total',
        '_line_tax',
        '_line_tax_data',
    );

    foreach ($prepared_items as $prepared) {
        $order_item = $prepared['item'];
        $new_item = new WC_Order_Item_Product();
        $new_item->set_product($prepared['product']);
        $new_item->set_quantity($prepared['quantity']);
        $new_item->set_subtotal($prepared['subtotal']);
        $new_item->set_total($prepared['total']);
        $new_item->set_subtotal_tax($prepared['subtotal_tax']);
        $new_item->set_total_tax($prepared['total_tax']);
        if (is_array($prepared['taxes'])) {
            $new_item->set_taxes($prepared['taxes']);
        }
        $variation_id = method_exists($order_item, 'get_variation_id') ? (int) $order_item->get_variation_id() : 0;
        if ($variation_id > 0) {
            $new_item->set_variation_id($variation_id);
        }
        $new_item->set_name($order_item->get_name());

        $meta_data = $order_item->get_meta_data();
        foreach ($meta_data as $meta) {
            $data = $meta->get_data();
            $key = isset($data['key']) ? (string) $data['key'] : '';
            if ($key === '' || in_array($key, $skip_meta_keys, true)) {
                continue;
            }
            $new_item->add_meta_data($key, $data['value'], true);
        }

        $new_order->add_item($new_item);
    }

    if ($order_id > 0) {
        $new_order->add_order_note('Restordre created from order #' . $order_id . ' (out of stock items).');
    } else {
        $new_order->add_order_note('Restordre created from out of stock items.');
    }
    $new_order->calculate_totals(false);
    $new_order->save();

    return $new_order;
}

function np_order_hub_wpo_apply_oos_split_to_order($order, $selected, $new_order = null) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return new WP_Error('order_not_found', 'Order not found.');
    }
    if (empty($selected) || !is_array($selected)) {
        return new WP_Error('missing_items', 'Missing items.');
    }

    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;
    foreach ($selected as $item_id => $qty) {
        $order_item = $order->get_item($item_id);
        if (!$order_item || !is_a($order_item, 'WC_Order_Item_Product')) {
            return new WP_Error('item_not_found', 'Item not found.');
        }
        $max_qty = (int) $order_item->get_quantity();
        $qty = (int) $qty;
        if ($max_qty < 1 || $qty < 1 || $qty > $max_qty) {
            return new WP_Error('invalid_quantity', 'Invalid quantity.');
        }

        if ($qty >= $max_qty) {
            $order->remove_item($item_id);
            continue;
        }

        $ratio = ($max_qty - $qty) / $max_qty;
        $subtotal = round((float) $order_item->get_subtotal() * $ratio, $precision);
        $total = round((float) $order_item->get_total() * $ratio, $precision);
        $subtotal_tax = round((float) $order_item->get_subtotal_tax() * $ratio, $precision);
        $total_tax = round((float) $order_item->get_total_tax() * $ratio, $precision);
        $taxes = np_order_hub_wpo_scale_taxes($order_item->get_taxes(), $ratio, $precision);

        $order_item->set_quantity($max_qty - $qty);
        $order_item->set_subtotal($subtotal);
        $order_item->set_total($total);
        $order_item->set_subtotal_tax($subtotal_tax);
        $order_item->set_total_tax($total_tax);
        if (is_array($taxes)) {
            $order_item->set_taxes($taxes);
        }
        $order_item->save();
    }

    $order->calculate_totals(false);
    if ($new_order && is_a($new_order, 'WC_Order')) {
        $label = method_exists($new_order, 'get_order_number') ? (string) $new_order->get_order_number() : (string) $new_order->get_id();
        $order->add_order_note('Out of stock items moved to restordre order #' . $label . '.');
        $order->update_meta_data('_np_restordre_split_order', $new_order->get_id());
    }
    $order->save();

    return true;
}

function np_order_hub_wpo_create_reklamasjon_order(WP_REST_Request $request) {
    $params = np_order_hub_wpo_get_request_params($request);
    $order_id = isset($params['order_id']) ? absint($params['order_id']) : 0;
    $items = isset($params['items']) ? $params['items'] : array();
    $allow_oos = array_key_exists('allow_oos', $params) ? filter_var($params['allow_oos'], FILTER_VALIDATE_BOOLEAN) : false;
    $token = isset($params['token']) ? (string) $params['token'] : '';
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('reklamasjon_create_request', array(
        'order_id' => $order_id,
        'has_items' => !empty($items),
        'allow_oos' => $allow_oos ? 'yes' : 'no',
        'token_present' => $token !== '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1) {
        return new WP_REST_Response(array('error' => 'missing_order_id'), 400);
    }
    if (is_string($items)) {
        $decoded = json_decode($items, true);
        if (is_array($decoded)) {
            $items = $decoded;
        }
    }
    if (!is_array($items) || empty($items)) {
        return new WP_REST_Response(array('error' => 'missing_items'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }

    $order = wc_get_order($order_id);
    if (!$order) {
        return new WP_REST_Response(array('error' => 'order_not_found'), 404);
    }

    $selected = np_order_hub_wpo_normalize_reklamasjon_items($items);
    if (empty($selected)) {
        return new WP_REST_Response(array('error' => 'missing_items'), 400);
    }

    $new_order = np_order_hub_wpo_create_reklamasjon_order_from_order($order, $selected, $allow_oos);
    if (is_wp_error($new_order)) {
        $code = $new_order->get_error_code();
        $status = 500;
        if (in_array($code, array('missing_items', 'item_not_found', 'invalid_quantity', 'product_not_found'), true)) {
            $status = 400;
        } elseif ($code === 'order_not_found') {
            $status = 404;
        } elseif ($code === 'stock_unavailable') {
            $status = 409;
        }
        return new WP_REST_Response(array('error' => $new_order->get_error_message()), $status);
    }

    return new WP_REST_Response(array(
        'status' => 'ok',
        'order_id' => $new_order->get_id(),
        'order_number' => method_exists($new_order, 'get_order_number') ? $new_order->get_order_number() : (string) $new_order->get_id(),
    ), 200);
}

function np_order_hub_get_wpo_document($order) {
    if (function_exists('wcpdf_get_document')) {
        return wcpdf_get_document('packing-slip', $order);
    }
    if (function_exists('\\WPO\\wcpdf_get_document')) {
        return \WPO\wcpdf_get_document('packing-slip', $order);
    }
    if (function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document')) {
        return \WPO\WC\PDF_Invoices\wcpdf_get_document('packing-slip', $order);
    }
    return null;
}

function np_order_hub_get_wpo_document_link($document, $order, &$source = '') {
    $url = '';
    $source = '';
    if (is_object($document) && method_exists($document, 'get_document_link')) {
        $url = (string) $document->get_document_link();
        if ($url !== '') {
            $source = 'document.get_document_link';
        }
    } elseif (is_object($document) && method_exists($document, 'get_url')) {
        $url = (string) $document->get_url();
        if ($url !== '') {
            $source = 'document.get_url';
        }
    }
    if ($url === '' && function_exists('wcpdf_get_document_link')) {
        $url = (string) wcpdf_get_document_link('packing-slip', $order);
        if ($url !== '') {
            $source = 'wcpdf_get_document_link';
        }
    }
    if ($url === '' && function_exists('\\WPO\\wcpdf_get_document_link')) {
        $url = (string) \WPO\wcpdf_get_document_link('packing-slip', $order);
        if ($url !== '') {
            $source = 'WPO\\wcpdf_get_document_link';
        }
    }
    if ($url === '' && function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document_link')) {
        $url = (string) \WPO\WC\PDF_Invoices\wcpdf_get_document_link('packing-slip', $order);
        if ($url !== '') {
            $source = 'WPO\\WC\\PDF_Invoices\\wcpdf_get_document_link';
        }
    }
    $url = esc_url_raw($url);
    return is_string($url) ? $url : '';
}

function np_order_hub_extract_access_key_from_url($url) {
    $url = (string) $url;
    if ($url === '') {
        return '';
    }
    $parsed = wp_parse_url($url);
    if (empty($parsed['query'])) {
        return '';
    }
    parse_str($parsed['query'], $params);
    if (empty($params['access_key'])) {
        return '';
    }
    return sanitize_text_field((string) $params['access_key']);
}

function np_order_hub_add_wpo_access_key($payload, $resource, $resource_id, $webhook_id) {
    np_order_hub_wpo_log('webhook_payload_start', array(
        'resource' => $resource,
        'resource_id' => $resource_id,
        'webhook_id' => $webhook_id,
    ));
    np_order_hub_wpo_log('webhook_payload_functions', array(
        'has_wcpdf_get_document' => function_exists('wcpdf_get_document'),
        'has_wpo_wcpdf_get_document' => function_exists('\\WPO\\wcpdf_get_document'),
        'has_wpo_wc_pdf_wcpdf_get_document' => function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document'),
        'has_wcpdf_get_document_link' => function_exists('wcpdf_get_document_link'),
        'has_wpo_wcpdf_get_document_link' => function_exists('\\WPO\\wcpdf_get_document_link'),
        'has_wpo_wc_pdf_wcpdf_get_document_link' => function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document_link'),
    ));
    if ($resource !== 'order') {
        np_order_hub_wpo_log('webhook_payload_skip_resource', array('resource' => $resource));
        return $payload;
    }
    if (!function_exists('wc_get_order')) {
        np_order_hub_wpo_log('webhook_payload_missing_wc_get_order');
        return $payload;
    }

    $order = wc_get_order($resource_id);
    if (!$order) {
        np_order_hub_wpo_log('webhook_payload_order_missing', array('resource_id' => $resource_id));
        return $payload;
    }

    $document = np_order_hub_get_wpo_document($order);
    if (!$document || is_wp_error($document)) {
        np_order_hub_wpo_log('webhook_payload_document_missing', array(
            'resource_id' => $resource_id,
            'is_error' => is_wp_error($document),
            'error_code' => is_wp_error($document) ? $document->get_error_code() : '',
            'error_message' => is_wp_error($document) ? $document->get_error_message() : '',
        ));
        return $payload;
    }
    np_order_hub_wpo_log('webhook_payload_document_class', array(
        'resource_id' => $resource_id,
        'class' => is_object($document) ? get_class($document) : gettype($document),
        'has_get_access_key' => is_object($document) && method_exists($document, 'get_access_key'),
        'has_get_document_link' => is_object($document) && method_exists($document, 'get_document_link'),
        'has_get_url' => is_object($document) && method_exists($document, 'get_url'),
    ));

    $access_key = '';
    if (is_object($document) && method_exists($document, 'get_access_key')) {
        $access_key = (string) $document->get_access_key();
    }
    np_order_hub_wpo_log('webhook_payload_access_key_from_document', array(
        'resource_id' => $resource_id,
        'access_key' => $access_key,
    ));

    if ($access_key === '') {
        $access_key = (string) $order->get_meta('_wcpdf_packing-slip_access_key', true);
        if ($access_key !== '') {
            np_order_hub_wpo_log('webhook_payload_access_key_from_meta', array(
                'resource_id' => $resource_id,
                'meta_key' => '_wcpdf_packing-slip_access_key',
                'access_key' => $access_key,
            ));
        }
    }
    if ($access_key === '') {
        $access_key = (string) $order->get_meta('_wcpdf_packing_slip_access_key', true);
        if ($access_key !== '') {
            np_order_hub_wpo_log('webhook_payload_access_key_from_meta', array(
                'resource_id' => $resource_id,
                'meta_key' => '_wcpdf_packing_slip_access_key',
                'access_key' => $access_key,
            ));
        }
    }
    np_order_hub_wpo_log('webhook_payload_meta_keys', array(
        'resource_id' => $resource_id,
        'meta_dash' => (string) $order->get_meta('_wcpdf_packing-slip_access_key', true),
        'meta_underscore' => (string) $order->get_meta('_wcpdf_packing_slip_access_key', true),
    ));

    $document_source = '';
    $document_url = np_order_hub_get_wpo_document_link($document, $order, $document_source);
    if ($document_url !== '') {
        $payload['np_wpo_packing_slip_url'] = $document_url;
    }
    np_order_hub_wpo_log('webhook_payload_document_url', array(
        'resource_id' => $resource_id,
        'document_url' => $document_url,
        'source' => $document_source,
    ));

    if ($access_key === '' && $document_url !== '') {
        $access_key = np_order_hub_extract_access_key_from_url($document_url);
        np_order_hub_wpo_log('webhook_payload_access_key_from_url', array(
            'resource_id' => $resource_id,
            'access_key' => $access_key,
        ));
    }

    if ($access_key !== '') {
        $payload['np_wpo_access_key'] = $access_key;
    }

    $reklamasjon_source = '';
    if (method_exists($order, 'get_meta')) {
        $reklamasjon_source = (string) $order->get_meta('_np_reklamasjon_source_order', true);
    }
    $is_reklamasjon = $reklamasjon_source !== '';
    if (!$is_reklamasjon && method_exists($order, 'get_status')) {
        $is_reklamasjon = $order->get_status() === 'reklamasjon';
    }
    if ($is_reklamasjon) {
        $payload['np_reklamasjon'] = true;
        if ($reklamasjon_source !== '') {
            $payload['np_reklamasjon_source_order'] = (int) $reklamasjon_source;
        }
    }

    $payload['np_order_hub_delivery_bucket'] = np_order_hub_wpo_get_default_delivery_bucket();

    np_order_hub_wpo_log('webhook_payload_done', array(
        'resource_id' => $resource_id,
        'has_access_key' => $access_key !== '',
        'has_packing_slip_url' => $document_url !== '',
    ));

    return $payload;
}
