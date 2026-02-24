<?php
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
    $order_prefix = function_exists('np_order_hub_wpo_get_order_prefix_for_blog')
        ? np_order_hub_wpo_get_order_prefix_for_blog(get_current_blog_id())
        : '';
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
    echo '<tr><th>Order number format</th><td><code>' . esc_html($order_prefix !== '' ? ($order_prefix . '-{order_id}') : '{order_id}') . '</code>';
    if ($order_prefix === '') {
        echo '<p class="description">Root site uses plain order numbers without prefix.</p>';
    } else {
        echo '<p class="description">Prefix identifies this subsite in the multisite network.</p>';
    }
    echo '</td></tr>';
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
