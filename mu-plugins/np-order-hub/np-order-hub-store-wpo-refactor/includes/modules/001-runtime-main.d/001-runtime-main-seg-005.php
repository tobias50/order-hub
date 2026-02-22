<?php
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