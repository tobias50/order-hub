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

$np_order_hub_wpo_main_file = defined('NP_ORDER_HUB_WPO_MAIN_FILE') ? NP_ORDER_HUB_WPO_MAIN_FILE : __FILE__;
register_activation_hook($np_order_hub_wpo_main_file, 'np_order_hub_wpo_activate');

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