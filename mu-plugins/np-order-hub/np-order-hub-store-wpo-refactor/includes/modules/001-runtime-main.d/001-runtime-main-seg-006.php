<?php
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
    register_rest_route('np-order-hub/v1', '/order-exists', array(
        'methods' => 'GET',
        'callback' => 'np_order_hub_wpo_order_exists',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/order-state', array(
        'methods' => 'GET',
        'callback' => 'np_order_hub_wpo_order_state',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('np-order-hub/v1', '/orders-export', array(
        'methods' => 'GET',
        'callback' => 'np_order_hub_wpo_orders_export',
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
