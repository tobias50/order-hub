<?php
function np_order_hub_reklamasjon_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_reklamasjon_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $reklamasjon_totals = np_order_hub_query_reklamasjon_totals(
        array('store' => $filters['store']),
        $filters['date_from'],
        $filters['date_to']
    );
    $reklamasjon_rows = np_order_hub_query_reklamasjon_by_store($filters);
    $orders = np_order_hub_query_reklamasjon_orders($filters, 500);

    $currency_label = '';
    if (!empty($reklamasjon_rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $reklamasjon_rows))));
        if (count($currencies) === 1) {
            $currency_label = (string) $currencies[0];
        }
    }

    $product_rows = array();
    foreach ($orders as $order) {
        if (!is_array($order)) {
            continue;
        }
        $payload = !empty($order['payload']) ? json_decode((string) $order['payload'], true) : null;
        if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
            continue;
        }
        $store_key = isset($order['store_key']) ? (string) $order['store_key'] : '';
        $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
        $currency = isset($order['currency']) ? (string) $order['currency'] : '';

        foreach ($payload['line_items'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? trim((string) $item['name']) : '';
            $sku = isset($item['sku']) ? trim((string) $item['sku']) : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;

            if ($qty < 1) {
                continue;
            }
            if ($name === '') {
                $name = 'Item';
            }
            $product_label = $sku !== '' ? ($name . ' (' . $sku . ')') : $name;
            $key = $store_key . '|' . $product_label;

            if (!isset($product_rows[$key])) {
                $product_rows[$key] = array(
                    'store_name' => $store_name !== '' ? $store_name : $store_key,
                    'product' => $product_label,
                    'qty' => 0,
                    'total' => 0.0,
                    'currency' => $currency,
                );
            }
            $product_rows[$key]['qty'] += $qty;
            $product_rows[$key]['total'] += $line_total;
            if ($product_rows[$key]['currency'] !== '' && $currency !== '' && $product_rows[$key]['currency'] !== $currency) {
                $product_rows[$key]['currency'] = '';
            }
        }
    }

    $product_rows = array_values($product_rows);
    usort($product_rows, function ($a, $b) {
        $store_cmp = strcmp((string) $a['store_name'], (string) $b['store_name']);
        if ($store_cmp !== 0) {
            return $store_cmp;
        }
        return strcmp((string) $a['product'], (string) $b['product']);
    });

    $base_url = admin_url('admin.php?page=np-order-hub-reklamasjon');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-reklamasjon-page">';
    echo '<h1>Reklamasjon</h1>';
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
    </style>';
    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-reklamasjon" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-store">Store</label>';
    echo '<select id="np-order-hub-rek-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-date-from">From</label>';
    echo '<input id="np-order-hub-rek-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rek-date-to">To</label>';
    echo '<input id="np-order-hub-rek-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $total_display = np_order_hub_format_money(
        isset($reklamasjon_totals['total']) ? (float) $reklamasjon_totals['total'] : 0.0,
        $currency_label
    );
    $count = isset($reklamasjon_totals['count']) ? (int) $reklamasjon_totals['count'] : 0;

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Reklamasjon totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
    echo '</div>';

    echo '<h2>Ordre</h2>';
    np_order_hub_render_order_list_table($orders, 'Ingen reklamasjon-ordre funnet.');

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($reklamasjon_rows)) {
        echo '<tr><td colspan="3">Ingen reklamasjon-ordre funnet.</td></tr>';
    } else {
        foreach ($reklamasjon_rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_display = np_order_hub_format_money($row_total, $row_currency);

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '<h2 style="margin-top:16px;">Produkter</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Produkt</th>';
    echo '<th>Antall</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($product_rows)) {
        echo '<tr><td colspan="4">Ingen reklamasjon-ordre funnet.</td></tr>';
    } else {
        foreach ($product_rows as $row) {
            $row_display = np_order_hub_format_money((float) $row['total'], (string) $row['currency']);
            echo '<tr>';
            echo '<td>' . esc_html($row['store_name']) . '</td>';
            echo '<td>' . esc_html($row['product']) . '</td>';
            echo '<td>' . esc_html((string) $row['qty']) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '</div>';
}

function np_order_hub_restordre_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_restordre_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $restordre_totals = np_order_hub_query_restordre_totals(
        array('store' => $filters['store']),
        $filters['date_from'],
        $filters['date_to']
    );
    $restordre_rows = np_order_hub_query_restordre_by_store($filters);
    $orders = np_order_hub_query_restordre_orders($filters, 500);

    $currency_label = '';
    if (!empty($restordre_rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $restordre_rows))));
        if (count($currencies) === 1) {
            $currency_label = (string) $currencies[0];
        }
    }

    $product_rows = array();
    foreach ($orders as $order) {
        if (!is_array($order)) {
            continue;
        }
        $payload = !empty($order['payload']) ? json_decode((string) $order['payload'], true) : null;
        if (!is_array($payload) || empty($payload['line_items']) || !is_array($payload['line_items'])) {
            continue;
        }
        $store_key = isset($order['store_key']) ? (string) $order['store_key'] : '';
        $store_name = isset($order['store_name']) ? (string) $order['store_name'] : '';
        $currency = isset($order['currency']) ? (string) $order['currency'] : '';

        foreach ($payload['line_items'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? trim((string) $item['name']) : '';
            $sku = isset($item['sku']) ? trim((string) $item['sku']) : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;

            if ($qty < 1) {
                continue;
            }
            if ($name === '') {
                $name = 'Item';
            }
            $product_label = $sku !== '' ? ($name . ' (' . $sku . ')') : $name;
            $key = $store_key . '|' . $product_label;

            if (!isset($product_rows[$key])) {
                $product_rows[$key] = array(
                    'store_name' => $store_name !== '' ? $store_name : $store_key,
                    'product' => $product_label,
                    'qty' => 0,
                    'total' => 0.0,
                    'currency' => $currency,
                );
            }
            $product_rows[$key]['qty'] += $qty;
            $product_rows[$key]['total'] += $line_total;
            if ($product_rows[$key]['currency'] !== '' && $currency !== '' && $product_rows[$key]['currency'] !== $currency) {
                $product_rows[$key]['currency'] = '';
            }
        }
    }

    $product_rows = array_values($product_rows);
    usort($product_rows, function ($a, $b) {
        $store_cmp = strcmp((string) $a['store_name'], (string) $b['store_name']);
        if ($store_cmp !== 0) {
            return $store_cmp;
        }
        return strcmp((string) $a['product'], (string) $b['product']);
    });

    $base_url = admin_url('admin.php?page=np-order-hub-restordre');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-restordre-page">';
    echo '<h1>Restordre</h1>';
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
    </style>';
    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-restordre" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-store">Store</label>';
    echo '<select id="np-order-hub-rest-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-date-from">From</label>';
    echo '<input id="np-order-hub-rest-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-rest-date-to">To</label>';
    echo '<input id="np-order-hub-rest-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $total_display = np_order_hub_format_money(
        isset($restordre_totals['total']) ? (float) $restordre_totals['total'] : 0.0,
        $currency_label
    );
    $count = isset($restordre_totals['count']) ? (int) $restordre_totals['count'] : 0;

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Restordre totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
    echo '</div>';

    echo '<h2>Ordre</h2>';
    np_order_hub_render_order_list_table($orders, 'Ingen restordre-ordre funnet.');

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($restordre_rows)) {
        echo '<tr><td colspan="3">Ingen restordre-ordre funnet.</td></tr>';
    } else {
        foreach ($restordre_rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_display = np_order_hub_format_money($row_total, $row_currency);

            echo '<tr>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '<h2 style="margin-top:16px;">Produkter</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Produkt</th>';
    echo '<th>Antall</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($product_rows)) {
        echo '<tr><td colspan="4">Ingen restordre-ordre funnet.</td></tr>';
    } else {
        foreach ($product_rows as $row) {
            $row_display = np_order_hub_format_money((float) $row['total'], (string) $row['currency']);
            echo '<tr>';
            echo '<td>' . esc_html($row['store_name']) . '</td>';
            echo '<td>' . esc_html($row['product']) . '</td>';
            echo '<td>' . esc_html((string) $row['qty']) . '</td>';
            echo '<td>' . esc_html($row_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '</div>';
}