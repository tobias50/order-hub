<?php
function np_order_hub_wpo_is_request_authorized(WP_REST_Request $request) {
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }
    return np_order_hub_wpo_check_token($token);
}

function np_order_hub_wpo_parse_decimal_input($value, $default = null) {
    if ($value === null || $value === '') {
        return $default;
    }
    if (is_string($value)) {
        $value = trim($value);
        $value = str_replace(' ', '', $value);
        $value = str_replace(',', '.', $value);
        $value = preg_replace('/[^0-9.\-]/', '', $value);
    }
    if ($value === '' || !is_numeric($value)) {
        return $default;
    }
    return (float) $value;
}

function np_order_hub_wpo_order_has_reduced_stock($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return false;
    }
    $flag = $order->get_meta('_order_stock_reduced', true);
    if ($flag === 'yes' || $flag === '1' || $flag === 1 || $flag === true) {
        return true;
    }
    return false;
}

function np_order_hub_wpo_build_stock_map_key($product_id, $variation_id) {
    $variation_id = absint($variation_id);
    $product_id = absint($product_id);
    if ($variation_id > 0) {
        return 'variation:' . $variation_id;
    }
    return 'product:' . $product_id;
}

function np_order_hub_wpo_collect_order_stock_map($order) {
    $map = array();
    if (!$order || !is_a($order, 'WC_Order')) {
        return $map;
    }
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
        $product_id = method_exists($item, 'get_product_id') ? (int) $item->get_product_id() : 0;
        $variation_id = method_exists($item, 'get_variation_id') ? (int) $item->get_variation_id() : 0;
        $key = np_order_hub_wpo_build_stock_map_key($product_id, $variation_id);
        if (!isset($map[$key])) {
            $map[$key] = array(
                'product' => $product,
                'quantity' => 0,
                'label' => method_exists($product, 'get_name') ? (string) $product->get_name() : ('Product ' . ($variation_id > 0 ? $variation_id : $product_id)),
            );
        }
        $map[$key]['quantity'] += $qty;
    }
    return $map;
}

function np_order_hub_wpo_apply_stock_delta_after_order_edit($order, $before_map) {
    if (!$order || !is_a($order, 'WC_Order') || !np_order_hub_wpo_order_has_reduced_stock($order)) {
        return array();
    }
    if (!function_exists('wc_update_product_stock')) {
        return array();
    }

    $after_map = np_order_hub_wpo_collect_order_stock_map($order);
    $keys = array_values(array_unique(array_merge(array_keys((array) $before_map), array_keys($after_map))));
    $changes = array();

    foreach ($keys as $key) {
        $before_qty = isset($before_map[$key]['quantity']) ? (int) $before_map[$key]['quantity'] : 0;
        $after_qty = isset($after_map[$key]['quantity']) ? (int) $after_map[$key]['quantity'] : 0;
        if ($before_qty === $after_qty) {
            continue;
        }
        $product = null;
        if (!empty($after_map[$key]['product']) && is_object($after_map[$key]['product'])) {
            $product = $after_map[$key]['product'];
        } elseif (!empty($before_map[$key]['product']) && is_object($before_map[$key]['product'])) {
            $product = $before_map[$key]['product'];
        }
        if (!$product) {
            continue;
        }
        $delta = $after_qty - $before_qty;
        $operation = $delta > 0 ? 'decrease' : 'increase';
        $adjust_by = abs($delta);
        if ($adjust_by < 1) {
            continue;
        }
        $result = wc_update_product_stock($product, $adjust_by, $operation);
        if (is_wp_error($result)) {
            continue;
        }
        $label = method_exists($product, 'get_name') ? (string) $product->get_name() : $key;
        $changes[] = sprintf('%s %s %d', $label, $operation === 'decrease' ? '-' : '+', $adjust_by);
    }

    if (!empty($changes)) {
        $order->add_order_note('Stock adjusted from Order Hub: ' . implode(', ', $changes));
        $order->save();
    }

    return $changes;
}

function np_order_hub_wpo_build_product_result_label($product) {
    if (!$product || !is_object($product)) {
        return '';
    }
    $label = method_exists($product, 'get_name') ? (string) $product->get_name() : 'Product';
    if ($product->is_type('variation')) {
        $parent_id = method_exists($product, 'get_parent_id') ? (int) $product->get_parent_id() : 0;
        $parent = $parent_id > 0 ? wc_get_product($parent_id) : null;
        if ($parent && method_exists($parent, 'get_name')) {
            $label = (string) $parent->get_name();
        }
        $attributes = method_exists($product, 'get_variation_attributes') ? (array) $product->get_variation_attributes() : array();
        $parts = array();
        foreach ($attributes as $attr_key => $attr_value) {
            $attr_key = (string) $attr_key;
            $attr_value = (string) $attr_value;
            if ($attr_value === '') {
                continue;
            }
            $taxonomy = str_replace('attribute_', '', $attr_key);
            $label_key = function_exists('wc_attribute_label') ? wc_attribute_label($taxonomy) : $taxonomy;
            $display_value = $attr_value;
            if (taxonomy_exists($taxonomy)) {
                $term = get_term_by('slug', $attr_value, $taxonomy);
                if ($term && !is_wp_error($term)) {
                    $display_value = $term->name;
                }
            }
            $parts[] = $label_key . ': ' . $display_value;
        }
        if (!empty($parts)) {
            $label .= ' (' . implode(', ', $parts) . ')';
        }
    }
    $sku = method_exists($product, 'get_sku') ? trim((string) $product->get_sku()) : '';
    if ($sku !== '') {
        $label .= ' [' . $sku . ']';
    }
    return $label;
}

function np_order_hub_wpo_search_order_products(WP_REST_Request $request) {
    if (!np_order_hub_wpo_is_request_authorized($request)) {
        return new WP_REST_Response(array('error' => 'Unauthorized.'), 401);
    }
    if (!function_exists('wc_get_products')) {
        return new WP_REST_Response(array('error' => 'WooCommerce missing.'), 500);
    }

    $query = sanitize_text_field((string) $request->get_param('q'));
    $limit = absint($request->get_param('limit'));
    if ($limit < 1) {
        $limit = 20;
    } elseif ($limit > 50) {
        $limit = 50;
    }

    if ($query === '' || mb_strlen($query) < 2) {
        return new WP_REST_Response(array('status' => 'ok', 'results' => array()), 200);
    }

    $products = wc_get_products(array(
        'status' => array('publish', 'private'),
        'limit' => $limit,
        's' => $query,
        'orderby' => 'title',
        'order' => 'ASC',
        'return' => 'objects',
    ));

    $results = array();
    $seen = array();
    foreach ((array) $products as $product) {
        if (!$product || !is_object($product)) {
            continue;
        }
        if ($product->is_type('variable')) {
            $children = method_exists($product, 'get_children') ? (array) $product->get_children() : array();
            foreach ($children as $variation_id) {
                $variation = wc_get_product($variation_id);
                if (!$variation || !$variation->exists()) {
                    continue;
                }
                $key = np_order_hub_wpo_build_stock_map_key($product->get_id(), $variation->get_id());
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $results[] = array(
                    'product_id' => (int) $product->get_id(),
                    'variation_id' => (int) $variation->get_id(),
                    'label' => np_order_hub_wpo_build_product_result_label($variation),
                    'sku' => (string) $variation->get_sku(),
                    'price' => wc_format_decimal((float) $variation->get_price(), wc_get_price_decimals()),
                    'stock_status' => method_exists($variation, 'get_stock_status') ? (string) $variation->get_stock_status() : '',
                    'stock_quantity' => method_exists($variation, 'get_stock_quantity') ? $variation->get_stock_quantity() : null,
                );
            }
            continue;
        }

        $key = np_order_hub_wpo_build_stock_map_key($product->get_id(), 0);
        if (isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $results[] = array(
            'product_id' => (int) $product->get_id(),
            'variation_id' => 0,
            'label' => np_order_hub_wpo_build_product_result_label($product),
            'sku' => (string) $product->get_sku(),
            'price' => wc_format_decimal((float) $product->get_price(), wc_get_price_decimals()),
            'stock_status' => method_exists($product, 'get_stock_status') ? (string) $product->get_stock_status() : '',
            'stock_quantity' => method_exists($product, 'get_stock_quantity') ? $product->get_stock_quantity() : null,
        );
    }

    usort($results, function ($a, $b) {
        return strcasecmp((string) ($a['label'] ?? ''), (string) ($b['label'] ?? ''));
    });
    if (count($results) > $limit) {
        $results = array_slice($results, 0, $limit);
    }

    return new WP_REST_Response(array('status' => 'ok', 'results' => $results), 200);
}

function np_order_hub_wpo_update_order_items(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $items = isset($params['items']) && is_array($params['items']) ? $params['items'] : array();
    if (empty($items)) {
        return new WP_REST_Response(array('error' => 'Missing items.'), 400);
    }

    $before_stock = np_order_hub_wpo_collect_order_stock_map($order);
    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;

    foreach ($items as $item_row) {
        if (!is_array($item_row)) {
            continue;
        }
        $item_id = isset($item_row['item_id']) ? absint($item_row['item_id']) : 0;
        if ($item_id < 1) {
            continue;
        }
        $order_item = $order->get_item($item_id);
        if (!$order_item || !is_a($order_item, 'WC_Order_Item_Product')) {
            return new WP_REST_Response(array('error' => 'Order item not found.'), 404);
        }

        $remove = !empty($item_row['remove']);
        $quantity = isset($item_row['quantity']) ? absint($item_row['quantity']) : (int) $order_item->get_quantity();
        if ($remove || $quantity < 1) {
            $order->remove_item($item_id);
            continue;
        }

        $current_qty = max(1, (int) $order_item->get_quantity());
        $current_subtotal = (float) $order_item->get_subtotal();
        $current_total = (float) $order_item->get_total();
        $current_subtotal_tax = (float) $order_item->get_subtotal_tax();
        $current_total_tax = (float) $order_item->get_total_tax();
        $current_taxes = $order_item->get_taxes();

        $unit_price = np_order_hub_wpo_parse_decimal_input($item_row['unit_price'] ?? null, null);
        if ($unit_price === null) {
            $unit_price = $current_qty > 0 ? ($current_total / $current_qty) : 0.0;
        }
        $new_subtotal = round($unit_price * $quantity, $precision);
        $new_total = round($unit_price * $quantity, $precision);
        $ratio = $current_subtotal != 0.0 ? ($new_subtotal / $current_subtotal) : ($quantity / max(1, $current_qty));

        $order_item->set_quantity($quantity);
        $order_item->set_subtotal($new_subtotal);
        $order_item->set_total($new_total);
        $order_item->set_subtotal_tax(round($current_subtotal_tax * $ratio, $precision));
        $order_item->set_total_tax(round($current_total_tax * $ratio, $precision));
        if (is_array($current_taxes)) {
            $order_item->set_taxes(np_order_hub_wpo_scale_taxes($current_taxes, $ratio, $precision));
        }
        $order_item->save();
    }

    $order->calculate_totals(false);
    $order->save();
    np_order_hub_wpo_apply_stock_delta_after_order_edit($order, $before_stock);

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_add_order_item(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }
    if (!class_exists('WC_Order_Item_Product')) {
        return new WP_REST_Response(array('error' => 'WooCommerce item classes missing.'), 500);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $product_id = isset($params['product_id']) ? absint($params['product_id']) : 0;
    $variation_id = isset($params['variation_id']) ? absint($params['variation_id']) : 0;
    $quantity = isset($params['quantity']) ? absint($params['quantity']) : 1;
    $unit_price = np_order_hub_wpo_parse_decimal_input($params['unit_price'] ?? null, null);

    $target_product_id = $variation_id > 0 ? $variation_id : $product_id;
    if ($target_product_id < 1 || $quantity < 1) {
        return new WP_REST_Response(array('error' => 'Missing product or quantity.'), 400);
    }

    $product = wc_get_product($target_product_id);
    if (!$product || !$product->exists()) {
        return new WP_REST_Response(array('error' => 'Product not found.'), 404);
    }

    if ($product->is_type('variable') && $variation_id < 1) {
        return new WP_REST_Response(array('error' => 'Select a specific variation for variable products.'), 400);
    }

    if ($product->is_type('variation')) {
        $variation_id = (int) $product->get_id();
        $product_id = (int) $product->get_parent_id();
    }

    $before_stock = np_order_hub_wpo_collect_order_stock_map($order);
    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;
    if ($unit_price === null) {
        $unit_price = (float) $product->get_price();
    }

    $new_item = new WC_Order_Item_Product();
    $new_item->set_product($product);
    $new_item->set_quantity($quantity);
    $new_item->set_subtotal(round($unit_price * $quantity, $precision));
    $new_item->set_total(round($unit_price * $quantity, $precision));
    if ($variation_id > 0) {
        $new_item->set_variation_id($variation_id);
        if (method_exists($product, 'get_variation_attributes')) {
            $attributes = (array) $product->get_variation_attributes();
            if (method_exists($new_item, 'set_variation')) {
                $new_item->set_variation($attributes);
            }
            foreach ($attributes as $attr_key => $attr_value) {
                if ($attr_value === '') {
                    continue;
                }
                $taxonomy = str_replace('attribute_', '', (string) $attr_key);
                $display_key = function_exists('wc_attribute_label') ? wc_attribute_label($taxonomy) : $taxonomy;
                $display_value = (string) $attr_value;
                if (taxonomy_exists($taxonomy)) {
                    $term = get_term_by('slug', (string) $attr_value, $taxonomy);
                    if ($term && !is_wp_error($term)) {
                        $display_value = $term->name;
                    }
                }
                $new_item->add_meta_data($display_key, $display_value, true);
            }
        }
    }

    $order->add_item($new_item);
    $order->calculate_totals(false);
    $order->save();
    np_order_hub_wpo_apply_stock_delta_after_order_edit($order, $before_stock);

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_update_order_shipping(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }
    if (!class_exists('WC_Order_Item_Shipping')) {
        return new WP_REST_Response(array('error' => 'WooCommerce shipping items missing.'), 500);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $shipping_lines = isset($params['shipping_lines']) && is_array($params['shipping_lines']) ? $params['shipping_lines'] : array();
    $new_shipping = isset($params['new_shipping']) && is_array($params['new_shipping']) ? $params['new_shipping'] : array();
    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;

    foreach ($shipping_lines as $row) {
        if (!is_array($row)) {
            continue;
        }
        $item_id = isset($row['item_id']) ? absint($row['item_id']) : 0;
        if ($item_id < 1) {
            continue;
        }
        $item = $order->get_item($item_id);
        if (!$item || !is_a($item, 'WC_Order_Item_Shipping')) {
            return new WP_REST_Response(array('error' => 'Shipping line not found.'), 404);
        }
        $remove = !empty($row['remove']);
        if ($remove) {
            $order->remove_item($item_id);
            continue;
        }
        $title = sanitize_text_field((string) ($row['method_title'] ?? $item->get_name()));
        $method_id = sanitize_key((string) ($row['method_id'] ?? $item->get_method_id()));
        $total = np_order_hub_wpo_parse_decimal_input($row['total'] ?? null, (float) $item->get_total());
        if (method_exists($item, 'set_method_title')) {
            $item->set_method_title($title);
        }
        $item->set_name($title);
        if ($method_id !== '' && method_exists($item, 'set_method_id')) {
            $item->set_method_id($method_id);
        }
        $item->set_total(round((float) $total, $precision));
        $item->set_total_tax(0);
        $item->save();
    }

    $new_title = sanitize_text_field((string) ($new_shipping['method_title'] ?? ''));
    $new_total = np_order_hub_wpo_parse_decimal_input($new_shipping['total'] ?? null, null);
    if ($new_title !== '' && $new_total !== null) {
        $new_item = new WC_Order_Item_Shipping();
        if (method_exists($new_item, 'set_method_title')) {
            $new_item->set_method_title($new_title);
        }
        $new_item->set_name($new_title);
        $new_item->set_method_id(sanitize_key((string) ($new_shipping['method_id'] ?? 'manual_shipping')) ?: 'manual_shipping');
        $new_item->set_total(round((float) $new_total, $precision));
        $new_item->set_total_tax(0);
        $order->add_item($new_item);
    }

    $order->calculate_totals(false);
    $order->save();

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_update_order_fees(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }
    if (!class_exists('WC_Order_Item_Fee')) {
        return new WP_REST_Response(array('error' => 'WooCommerce fee items missing.'), 500);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $fee_lines = isset($params['fee_lines']) && is_array($params['fee_lines']) ? $params['fee_lines'] : array();
    $new_fee = isset($params['new_fee']) && is_array($params['new_fee']) ? $params['new_fee'] : array();
    $precision = function_exists('wc_get_price_decimals') ? wc_get_price_decimals() : 2;

    foreach ($fee_lines as $row) {
        if (!is_array($row)) {
            continue;
        }
        $item_id = isset($row['item_id']) ? absint($row['item_id']) : 0;
        if ($item_id < 1) {
            continue;
        }
        $item = $order->get_item($item_id);
        if (!$item || !is_a($item, 'WC_Order_Item_Fee')) {
            return new WP_REST_Response(array('error' => 'Fee line not found.'), 404);
        }
        $remove = !empty($row['remove']);
        if ($remove) {
            $order->remove_item($item_id);
            continue;
        }
        $name = sanitize_text_field((string) ($row['name'] ?? $item->get_name()));
        $amount = np_order_hub_wpo_parse_decimal_input($row['amount'] ?? null, (float) $item->get_total());
        $item->set_name($name);
        if (method_exists($item, 'set_amount')) {
            $item->set_amount(round((float) $amount, $precision));
        }
        $item->set_total(round((float) $amount, $precision));
        $item->set_total_tax(0);
        if (method_exists($item, 'set_tax_class')) {
            $item->set_tax_class('');
        }
        if (method_exists($item, 'set_tax_status')) {
            $item->set_tax_status('none');
        }
        $item->save();
    }

    $new_name = sanitize_text_field((string) ($new_fee['name'] ?? ''));
    $new_amount = np_order_hub_wpo_parse_decimal_input($new_fee['amount'] ?? null, null);
    if ($new_name !== '' && $new_amount !== null) {
        $new_item = new WC_Order_Item_Fee();
        $new_item->set_name($new_name);
        if (method_exists($new_item, 'set_amount')) {
            $new_item->set_amount(round((float) $new_amount, $precision));
        }
        $new_item->set_total(round((float) $new_amount, $precision));
        if (method_exists($new_item, 'set_tax_class')) {
            $new_item->set_tax_class('');
        }
        if (method_exists($new_item, 'set_tax_status')) {
            $new_item->set_tax_status('none');
        }
        $order->add_item($new_item);
    }

    $order->calculate_totals(false);
    $order->save();

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_recalculate_order_totals(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }
    $order->calculate_totals(false);
    $order->save();
    return np_order_hub_wpo_rest_success_response($order);
}
