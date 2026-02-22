<?php
function np_order_hub_query_produksjonsfeil_products($filters) {
    np_order_hub_ensure_production_error_table();

    global $wpdb;
    $table = np_order_hub_production_error_table_name();
    $args = array();
    $where = np_order_hub_build_produksjonsfeil_where_clause(is_array($filters) ? $filters : array(), $args);
    $sql = "SELECT store_key, store_name, product_name, size_label, sku, currency, COALESCE(SUM(quantity), 0) AS qty_total, COALESCE(SUM(total_cost), 0) AS cost_total
        FROM $table $where
        GROUP BY store_key, store_name, product_name, size_label, sku, currency
        ORDER BY store_name, product_name, size_label";
    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_record_is_reklamasjon($record) {
    if (!is_array($record)) {
        return false;
    }
    if (!empty($record['status']) && $record['status'] === 'reklamasjon') {
        return true;
    }
    if (empty($record['payload'])) {
        return false;
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return false;
    }
    if (!empty($payload['np_reklamasjon'])) {
        return true;
    }
    return !empty($payload['np_reklamasjon_source_order']);
}

function np_order_hub_record_is_bytte_storrelse($record) {
    if (!is_array($record)) {
        return false;
    }
    if (!empty($record['status']) && $record['status'] === 'bytte-storrelse') {
        return true;
    }
    if (empty($record['payload'])) {
        return false;
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return false;
    }
    if (!empty($payload['np_bytte_storrelse'])) {
        return true;
    }
    return !empty($payload['np_bytte_storrelse_source_order']);
}

function np_order_hub_record_delivery_bucket($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return 'standard';
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return 'standard';
    }
    $bucket = isset($payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY]) ? (string) $payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] : '';
    return $bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
}

function np_order_hub_update_delivery_bucket($record, $bucket) {
    if (!is_array($record) || empty($record['id'])) {
        return $record;
    }
    $bucket = np_order_hub_normalize_delivery_bucket($bucket);
    $payload = array();
    if (!empty($record['payload'])) {
        $decoded = json_decode((string) $record['payload'], true);
        if (!is_array($decoded)) {
            return $record;
        }
        $payload = $decoded;
    }
    $payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $bucket;
    $update = array(
        'payload' => wp_json_encode($payload),
        'updated_at_gmt' => current_time('mysql', true),
    );
    global $wpdb;
    $table = np_order_hub_table_name();
    $wpdb->update($table, $update, array('id' => (int) $record['id']));

    $record['payload'] = $update['payload'];
    return $record;
}

function np_order_hub_get_reklamasjon_item_summary($record) {
    $summary = array(
        'lines' => array(),
        'qty' => 0,
    );
    if (!is_array($record) || empty($record['payload'])) {
        return $summary;
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
        return $summary;
    }
    foreach ($payload['line_items'] as $item) {
        if (!is_array($item)) {
            continue;
        }
        $name = isset($item['name']) ? trim((string) $item['name']) : '';
        $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
        if ($qty < 1) {
            continue;
        }
        if ($name === '') {
            $name = 'Item';
        }
        $summary['lines'][] = $name . ' x ' . $qty;
        $summary['qty'] += $qty;
    }
    return $summary;
}

function np_order_hub_count_line_items($payload) {
    if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
        return 0;
    }
    $total = 0;
    foreach ($payload['line_items'] as $item) {
        if (!is_array($item)) {
            continue;
        }
        $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
        if ($qty > 0) {
            $total += $qty;
        }
    }
    return $total;
}

function np_order_hub_get_customer_label($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return '—';
    }
    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return '—';
    }
    $billing = isset($payload['billing']) && is_array($payload['billing']) ? $payload['billing'] : array();
    $first = isset($billing['first_name']) ? sanitize_text_field((string) $billing['first_name']) : '';
    $last = isset($billing['last_name']) ? sanitize_text_field((string) $billing['last_name']) : '';
    $name = trim($first . ' ' . $last);
    if ($name === '' && !empty($billing['company'])) {
        $name = sanitize_text_field((string) $billing['company']);
    }
    if ($name === '' && !empty($billing['email'])) {
        $name = sanitize_text_field((string) $billing['email']);
    }
    return $name !== '' ? $name : '—';
}

function np_order_hub_render_order_list_table($orders, $empty_message = 'No orders found.') {
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Order</th>';
    echo '<th>Customer</th>';
    echo '<th>Store</th>';
    echo '<th>Date</th>';
    echo '<th>Status</th>';
    echo '<th>Reklamasjon</th>';
    echo '<th>Total</th>';
    echo '<th>Actions</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($orders)) {
        echo '<tr><td colspan="8">' . esc_html($empty_message) . '</td></tr>';
    } else {
        foreach ($orders as $order) {
            if (!is_array($order)) {
                continue;
            }
            $order_id = isset($order['order_id']) ? (int) $order['order_id'] : 0;
            $order_number = isset($order['order_number']) ? (string) $order['order_number'] : '';
            $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
            $customer_label = np_order_hub_get_customer_label($order);
            $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
            $date_label = '';
            if (!empty($order['date_created_gmt']) && $order['date_created_gmt'] !== '0000-00-00 00:00:00') {
                $date_label = get_date_from_gmt($order['date_created_gmt'], 'd.m.y');
            }
            $status_label = '';
            if (!empty($order['status'])) {
                $status_label = ucwords(str_replace('-', ' ', (string) $order['status']));
            }
            $total_display = np_order_hub_format_money(isset($order['total']) ? (float) $order['total'] : 0.0, isset($order['currency']) ? (string) $order['currency'] : '');
            $is_reklamasjon = np_order_hub_record_is_reklamasjon($order);
            $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $order['id']);
            $open_url = isset($order['order_admin_url']) ? (string) $order['order_admin_url'] : '';
            $store = np_order_hub_get_store_by_key(isset($order['store_key']) ? $order['store_key'] : '');
            $packing_url = np_order_hub_build_packing_slip_url(
                $store,
                $order_id,
                $order_number,
                isset($order['payload']) ? $order['payload'] : null
            );

            echo '<tr>';
            echo '<td>' . esc_html($label) . '</td>';
            echo '<td>' . esc_html($customer_label) . '</td>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html($date_label) . '</td>';
            echo '<td>';
            if ($status_label !== '') {
                echo '<span class="np-order-hub-status">' . esc_html($status_label) . '</span>';
            }
            echo '</td>';
            echo '<td>' . ($is_reklamasjon ? '<span class="np-order-hub-status">Ja</span>' : '—') . '</td>';
            echo '<td>' . esc_html($total_display) . '</td>';
            echo '<td class="np-order-hub-actions">';
            echo '<a class="button button-small" href="' . esc_url($details_url) . '">Details</a>';
            if ($packing_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
            }
            if ($open_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($open_url) . '" target="_blank" rel="noopener">Open order</a>';
            }
            echo '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';
}

function np_order_hub_query_orders($filters, $per_page, $offset, &$total_items, $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, true, true);
    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);

    $count_sql = "SELECT COUNT(*) FROM $table $where";
    $total_items = $args ? (int) $wpdb->get_var($wpdb->prepare($count_sql, $args)) : (int) $wpdb->get_var($count_sql);

    $query_sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d OFFSET %d";
    $query_args = array_merge($args, array((int) $per_page, (int) $offset));
    return $wpdb->get_results($wpdb->prepare($query_sql, $query_args), ARRAY_A);
}