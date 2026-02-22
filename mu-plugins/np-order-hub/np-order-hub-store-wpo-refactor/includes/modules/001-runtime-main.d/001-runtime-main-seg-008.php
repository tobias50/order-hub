<?php
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