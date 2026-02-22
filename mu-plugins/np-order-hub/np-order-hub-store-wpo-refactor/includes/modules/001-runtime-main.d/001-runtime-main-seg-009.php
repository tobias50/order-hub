<?php
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