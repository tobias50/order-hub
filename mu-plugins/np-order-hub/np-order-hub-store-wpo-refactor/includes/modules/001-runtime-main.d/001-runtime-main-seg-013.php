<?php
function np_order_hub_wpo_selected_class_meta_keys() {
    return array(
        'selected_class',
        '_selected_class',
        'selected_class_name',
        'selected_class_value',
        'selected class',
        'selected class:',
        'klasse',
        'klasse:',
        'np_selected_class',
        '_np_selected_class',
        'school_class',
        'class_selection',
        '_class_selection',
        '_class',
        'class',
    );
}

function np_order_hub_wpo_normalize_selected_class_key($key) {
    $key = strtolower(trim(wp_strip_all_tags((string) $key)));
    $key = str_replace(array('-', ':', '  '), array('_', '', ' '), $key);
    $key = preg_replace('/\s+/', '_', $key);
    return is_string($key) ? $key : '';
}

function np_order_hub_wpo_is_selected_class_meta_key($key) {
    $normalized = np_order_hub_wpo_normalize_selected_class_key($key);
    if ($normalized === '') {
        return false;
    }

    $keys = array_map('np_order_hub_wpo_normalize_selected_class_key', np_order_hub_wpo_selected_class_meta_keys());
    return in_array($normalized, $keys, true);
}

function np_order_hub_wpo_clean_selected_class_text($value) {
    if (is_array($value)) {
        foreach ($value as $item) {
            $found = np_order_hub_wpo_clean_selected_class_text($item);
            if ($found !== '') {
                return $found;
            }
        }
        return '';
    }

    if (is_object($value)) {
        if (method_exists($value, 'get_data')) {
            return np_order_hub_wpo_clean_selected_class_text($value->get_data());
        }
        return np_order_hub_wpo_clean_selected_class_text((array) $value);
    }

    if (!is_scalar($value)) {
        return '';
    }

    $text = trim(wp_strip_all_tags((string) $value));
    if ($text === '') {
        return '';
    }

    if (preg_match('/(?:selected\s*class|klasse)\s*:?\s*(.+)$/iu', $text, $matches)) {
        $text = trim((string) $matches[1]);
    }

    return sanitize_text_field($text);
}

function np_order_hub_wpo_get_selected_class_payload($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return '';
    }

    if (function_exists('np_ps_get_selected_class')) {
        $selected_class = np_order_hub_wpo_clean_selected_class_text(np_ps_get_selected_class($order));
        if ($selected_class !== '') {
            return $selected_class;
        }
    }

    foreach (np_order_hub_wpo_selected_class_meta_keys() as $meta_key) {
        $post_meta_value = np_order_hub_wpo_clean_selected_class_text(get_post_meta((int) $order->get_id(), $meta_key, true));
        if ($post_meta_value !== '') {
            return $post_meta_value;
        }
        $value = np_order_hub_wpo_clean_selected_class_text($order->get_meta($meta_key, true));
        if ($value !== '') {
            return $value;
        }
    }

    foreach ((array) $order->get_meta_data() as $meta) {
        if (!is_object($meta) || !method_exists($meta, 'get_data')) {
            continue;
        }
        $data = $meta->get_data();
        if (!is_array($data)) {
            continue;
        }
        $key = (string) ($data['key'] ?? '');
        $value = $data['value'] ?? '';
        if (np_order_hub_wpo_is_selected_class_meta_key($key)) {
            $selected_class = np_order_hub_wpo_clean_selected_class_text($value);
            if ($selected_class !== '') {
                return $selected_class;
            }
        }
        $selected_class = np_order_hub_wpo_clean_selected_class_text($value);
        if ($selected_class !== '' && preg_match('/(?:selected\s*class|klasse)/iu', (string) $value)) {
            return $selected_class;
        }
    }

    foreach ($order->get_items('line_item') as $item) {
        if (!$item || !is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }
        foreach ((array) $item->get_meta_data() as $meta) {
            if (!is_object($meta) || !method_exists($meta, 'get_data')) {
                continue;
            }
            $data = $meta->get_data();
            if (!is_array($data)) {
                continue;
            }
            $key = (string) ($data['key'] ?? '');
            $value = $data['value'] ?? '';
            if (np_order_hub_wpo_is_selected_class_meta_key($key)) {
                $selected_class = np_order_hub_wpo_clean_selected_class_text($value);
                if ($selected_class !== '') {
                    return $selected_class;
                }
            }
            $selected_class = np_order_hub_wpo_clean_selected_class_text($value);
            if ($selected_class !== '' && preg_match('/(?:selected\s*class|klasse)/iu', (string) $value)) {
                return $selected_class;
            }
        }
    }

    $address_candidates = array(
        method_exists($order, 'get_formatted_billing_address') ? (string) $order->get_formatted_billing_address() : '',
        method_exists($order, 'get_formatted_shipping_address') ? (string) $order->get_formatted_shipping_address() : '',
    );
    foreach ($address_candidates as $candidate) {
        $selected_class = np_order_hub_wpo_clean_selected_class_text($candidate);
        if ($selected_class !== '' && preg_match('/(?:selected\s*class|klasse)/iu', $candidate)) {
            return $selected_class;
        }
    }

    return '';
}

function np_order_hub_wpo_get_live_order_payload($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return array();
    }

    $payload = np_order_hub_wpo_build_order_payload_for_hub($order);
    if (!is_array($payload)) {
        $payload = array();
    }

    $payload['billing'] = is_array($order->get_address('billing')) ? $order->get_address('billing') : array();
    $payload['shipping'] = is_array($order->get_address('shipping')) ? $order->get_address('shipping') : array();
    $payload['customer_note'] = (string) $order->get_customer_note();
    $payload['order_notes'] = np_order_hub_wpo_get_order_notes_payload($order);
    $payload['selected_class'] = np_order_hub_wpo_get_selected_class_payload($order);
    $payload['email_actions'] = np_order_hub_wpo_get_allowed_email_actions();

    return $payload;
}

function np_order_hub_wpo_get_order_notes_payload($order) {
    if (!$order || !is_a($order, 'WC_Order')) {
        return array();
    }

    $notes = array();
    if (function_exists('wc_get_order_notes')) {
        $notes = wc_get_order_notes(array(
            'order_id' => (int) $order->get_id(),
            'limit' => 20,
            'orderby' => 'date_created_gmt',
            'order' => 'DESC',
        ));
    }
    if ((!is_array($notes) || empty($notes)) && function_exists('get_comments')) {
        $notes = get_comments(array(
            'post_id' => (int) $order->get_id(),
            'type' => 'order_note',
            'status' => 'approve',
            'number' => 20,
            'orderby' => 'comment_date_gmt',
            'order' => 'DESC',
        ));
    }
    if (!is_array($notes)) {
        return array();
    }

    $items = array();
    foreach ($notes as $note) {
        if (!is_object($note)) {
            continue;
        }
        $content = '';
        if (method_exists($note, 'get_content')) {
            $content = (string) $note->get_content();
        } elseif (isset($note->comment_content)) {
            $content = (string) $note->comment_content;
        } elseif (isset($note->content)) {
            $content = (string) $note->content;
        }
        $content = trim(wp_strip_all_tags($content));
        if ($content === '') {
            continue;
        }

        $date_created_gmt = '';
        if (method_exists($note, 'get_date_created')) {
            $date_created_gmt = np_order_hub_wpo_iso_datetime($note->get_date_created(), true);
        } elseif (isset($note->comment_date_gmt)) {
            $date_created_gmt = trim((string) $note->comment_date_gmt);
        } elseif (isset($note->date_created_gmt)) {
            $date_created_gmt = trim((string) $note->date_created_gmt);
        }

        $added_by = '';
        if (method_exists($note, 'get_added_by')) {
            $added_by = (string) $note->get_added_by();
        } elseif (isset($note->comment_author)) {
            $added_by = (string) $note->comment_author;
        } elseif (isset($note->added_by)) {
            $added_by = (string) $note->added_by;
        }

        $is_customer_note = method_exists($note, 'get_customer_note')
            ? (bool) $note->get_customer_note()
            : (!empty($note->customer_note));
        if (!$is_customer_note && isset($note->comment_ID)) {
            $is_customer_note = get_comment_meta((int) $note->comment_ID, 'is_customer_note', true) === '1';
        }

        $added_by_user = method_exists($note, 'get_added_by_user')
            ? (bool) $note->get_added_by_user()
            : (!empty($note->added_by_user));
        if (!$added_by_user && isset($note->user_id)) {
            $added_by_user = ((int) $note->user_id) > 0;
        }

        $items[] = array(
            'id' => method_exists($note, 'get_id') ? (int) $note->get_id() : (isset($note->id) ? (int) $note->id : 0),
            'note' => $content,
            'is_customer_note' => $is_customer_note,
            'added_by_user' => $added_by_user,
            'added_by' => sanitize_text_field($added_by),
            'date_created_gmt' => $date_created_gmt,
        );
    }

    return $items;
}

function np_order_hub_wpo_get_allowed_email_actions() {
    return array(
        'customer_processing_order' => 'Processing order',
        'customer_completed_order' => 'Completed order',
        'customer_invoice' => 'Order details / invoice',
    );
}

function np_order_hub_wpo_get_authenticated_order_from_request(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_Error('unauthorized', 'Unauthorized.', array('status' => 401));
    }
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.', array('status' => 400));
    }
    if (!function_exists('wc_get_order')) {
        return new WP_Error('woocommerce_missing', 'WooCommerce missing.', array('status' => 500));
    }

    $order = wc_get_order($order_id);
    if (!$order || !is_a($order, 'WC_Order')) {
        return new WP_Error('order_not_found', 'Order not found.', array('status' => 404));
    }

    return $order;
}

function np_order_hub_wpo_rest_error_response($error) {
    if (!is_wp_error($error)) {
        return new WP_REST_Response(array('error' => 'unknown_error'), 500);
    }

    $status = 500;
    $data = $error->get_error_data();
    if (is_array($data) && !empty($data['status'])) {
        $status = (int) $data['status'];
    }

    return new WP_REST_Response(array(
        'error' => $error->get_error_message(),
        'code' => $error->get_error_code(),
    ), $status);
}

function np_order_hub_wpo_rest_success_response($order, $extra = array()) {
    $response = array(
        'status' => 'ok',
        'order' => np_order_hub_wpo_get_live_order_payload($order),
    );
    if (!empty($extra) && is_array($extra)) {
        $response = array_merge($response, $extra);
    }
    return new WP_REST_Response($response, 200);
}

function np_order_hub_wpo_sanitize_address_input($raw, $type) {
    $raw = is_array($raw) ? $raw : array();
    $type = $type === 'shipping' ? 'shipping' : 'billing';

    $fields = array(
        'first_name',
        'last_name',
        'company',
        'address_1',
        'address_2',
        'city',
        'state',
        'postcode',
        'country',
    );
    if ($type === 'billing') {
        $fields[] = 'email';
        $fields[] = 'phone';
    }
    if ($type === 'shipping') {
        $fields[] = 'phone';
    }

    $sanitized = array();
    foreach ($fields as $field) {
        if (!array_key_exists($field, $raw)) {
            continue;
        }
        $value = is_scalar($raw[$field]) ? (string) $raw[$field] : '';
        if ($field === 'email') {
            $sanitized[$field] = sanitize_email($value);
        } elseif ($field === 'country') {
            $sanitized[$field] = strtoupper(sanitize_text_field($value));
        } else {
            $sanitized[$field] = sanitize_text_field($value);
        }
    }

    return $sanitized;
}

function np_order_hub_wpo_order_live(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_update_order_addresses(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $billing = np_order_hub_wpo_sanitize_address_input(isset($params['billing']) ? $params['billing'] : array(), 'billing');
    $shipping = np_order_hub_wpo_sanitize_address_input(isset($params['shipping']) ? $params['shipping'] : array(), 'shipping');

    if (!empty($billing)) {
        $order->set_address($billing, 'billing');
        if (array_key_exists('phone', $billing) && method_exists($order, 'set_billing_phone')) {
            $order->set_billing_phone((string) $billing['phone']);
        }
        if (array_key_exists('email', $billing) && method_exists($order, 'set_billing_email')) {
            $order->set_billing_email((string) $billing['email']);
        }
    }
    if (!empty($shipping)) {
        $shipping_address = $shipping;
        unset($shipping_address['phone']);
        $order->set_address($shipping_address, 'shipping');
        if (array_key_exists('phone', $shipping) && method_exists($order, 'set_shipping_phone')) {
            $order->set_shipping_phone((string) $shipping['phone']);
        }
    }

    $order->save();

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_add_order_note(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $note = isset($params['note']) ? trim(wp_kses_post((string) $params['note'])) : '';
    if ($note === '') {
        return new WP_REST_Response(array('error' => 'Missing note.'), 400);
    }

    $order->add_order_note($note, 0, true);
    $order->save();

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_update_customer_note(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $note = isset($params['customer_note']) ? trim(wp_kses_post((string) $params['customer_note'])) : '';

    if (method_exists($order, 'set_customer_note')) {
        $order->set_customer_note($note);
        $order->save();
    }

    return np_order_hub_wpo_rest_success_response($order);
}

function np_order_hub_wpo_send_order_email(WP_REST_Request $request) {
    $order = np_order_hub_wpo_get_authenticated_order_from_request($request);
    if (is_wp_error($order)) {
        return np_order_hub_wpo_rest_error_response($order);
    }

    if (np_order_hub_wpo_is_outgoing_email_disabled()) {
        return new WP_REST_Response(array('error' => 'Outgoing email is disabled for this store.'), 409);
    }

    $params = np_order_hub_wpo_get_request_params($request);
    $action = sanitize_key((string) ($params['email_action'] ?? ''));
    $allowed = np_order_hub_wpo_get_allowed_email_actions();
    if (!isset($allowed[$action])) {
        return new WP_REST_Response(array('error' => 'Invalid email action.'), 400);
    }
    if (!function_exists('WC') || !WC() || !method_exists(WC(), 'mailer')) {
        return new WP_REST_Response(array('error' => 'WooCommerce mailer missing.'), 500);
    }

    $mailer = WC()->mailer();
    $emails = method_exists($mailer, 'get_emails') ? $mailer->get_emails() : array();
    $email_object = null;
    if (is_array($emails)) {
        foreach ($emails as $email) {
            if (!is_object($email) || !method_exists($email, 'trigger')) {
                continue;
            }
            $email_id = isset($email->id) ? sanitize_key((string) $email->id) : '';
            if ($email_id === $action) {
                $email_object = $email;
                break;
            }
        }
    }
    if (!$email_object) {
        return new WP_REST_Response(array('error' => 'Email action unavailable on this store.'), 404);
    }

    $email_object->trigger((int) $order->get_id(), $order);

    return np_order_hub_wpo_rest_success_response($order, array(
        'email_action' => $action,
    ));
}
