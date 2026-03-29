<?php
function np_order_hub_update_remote_order_items($store, $order_id, $items, $new_items = array()) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-items', 'POST', array(
        'order_id' => $order_id,
        'items' => is_array($items) ? $items : array(),
        'new_items' => is_array($new_items) ? $new_items : array(),
    ));
}

function np_order_hub_search_remote_order_products($store, $query, $limit = 20) {
    $query = sanitize_text_field((string) $query);
    if ($query === '') {
        return array('status' => 'ok', 'results' => array());
    }

    $limit = absint($limit);
    if ($limit < 1) {
        $limit = 20;
    } elseif ($limit > 50) {
        $limit = 50;
    }

    return np_order_hub_request_remote_order_endpoint($store, 'order-item-search', 'GET', array(
        'q' => $query,
        'limit' => $limit,
    ));
}

function np_order_hub_update_remote_order_shipping($store, $order_id, $shipping_lines, $new_shipping = array()) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-shipping', 'POST', array(
        'order_id' => $order_id,
        'shipping_lines' => is_array($shipping_lines) ? $shipping_lines : array(),
        'new_shipping' => is_array($new_shipping) ? $new_shipping : array(),
    ));
}

function np_order_hub_update_remote_order_fees($store, $order_id, $fee_lines, $new_fee = array()) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-fees', 'POST', array(
        'order_id' => $order_id,
        'fee_lines' => is_array($fee_lines) ? $fee_lines : array(),
        'new_fee' => is_array($new_fee) ? $new_fee : array(),
    ));
}

function np_order_hub_recalculate_remote_order($store, $order_id) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-recalculate', 'POST', array(
        'order_id' => $order_id,
    ));
}
