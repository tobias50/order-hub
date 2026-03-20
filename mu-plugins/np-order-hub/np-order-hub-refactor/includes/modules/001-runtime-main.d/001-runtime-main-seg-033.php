<?php
function np_order_hub_search_remote_order_products($store, $query, $limit = 20) {
    $query = sanitize_text_field((string) $query);
    if ($query === '') {
        return array('status' => 'ok', 'results' => array());
    }
    $limit = absint($limit);
    if ($limit < 1) {
        $limit = 20;
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-product-search', 'GET', array(
        'q' => $query,
        'limit' => $limit,
    ));
}

function np_order_hub_update_remote_order_items($store, $order_id, $items) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-items', 'POST', array(
        'order_id' => $order_id,
        'items' => is_array($items) ? $items : array(),
    ));
}

function np_order_hub_add_remote_order_item($store, $order_id, $product_id, $variation_id, $quantity, $unit_price = null) {
    $order_id = absint($order_id);
    $product_id = absint($product_id);
    $variation_id = absint($variation_id);
    $quantity = absint($quantity);
    if ($order_id < 1 || ($product_id < 1 && $variation_id < 1) || $quantity < 1) {
        return new WP_Error('missing_params', 'Missing product, quantity or order ID.');
    }
    $payload = array(
        'order_id' => $order_id,
        'product_id' => $product_id,
        'variation_id' => $variation_id,
        'quantity' => $quantity,
    );
    if ($unit_price !== null && $unit_price !== '') {
        $payload['unit_price'] = $unit_price;
    }
    return np_order_hub_request_remote_order_endpoint($store, 'order-item-add', 'POST', $payload);
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
