<?php
function np_order_hub_bytte_storrelse_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_bytte_storrelse_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $bytte_totals = np_order_hub_query_bytte_storrelse_totals(
        array('store' => $filters['store']),
        $filters['date_from'],
        $filters['date_to']
    );
    $bytte_rows = np_order_hub_query_bytte_storrelse_by_store($filters);
    $orders = np_order_hub_query_bytte_storrelse_orders($filters, 500);

    $currency_label = '';
    if (!empty($bytte_rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $bytte_rows))));
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

    $base_url = admin_url('admin.php?page=np-order-hub-bytte-storrelse');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-bytte-storrelse-page">';
    echo '<h1>Bytte størrelse</h1>';
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
    </style>';
    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-bytte-storrelse" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-bytte-store">Store</label>';
    echo '<select id="np-order-hub-bytte-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-bytte-date-from">From</label>';
    echo '<input id="np-order-hub-bytte-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-bytte-date-to">To</label>';
    echo '<input id="np-order-hub-bytte-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $total_display = np_order_hub_format_money(
        isset($bytte_totals['total']) ? (float) $bytte_totals['total'] : 0.0,
        $currency_label
    );
    $count = isset($bytte_totals['count']) ? (int) $bytte_totals['count'] : 0;

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Bytte størrelse totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
    echo '</div>';

    echo '<h2>Ordre</h2>';
    np_order_hub_render_order_list_table($orders, 'Ingen bytte størrelse-ordre funnet.');

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Total</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($bytte_rows)) {
        echo '<tr><td colspan="3">Ingen bytte størrelse-ordre funnet.</td></tr>';
    } else {
        foreach ($bytte_rows as $row) {
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
        echo '<tr><td colspan="4">Ingen bytte størrelse-ordre funnet.</td></tr>';
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

function np_order_hub_produksjonsfeil_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $filters = np_order_hub_get_produksjonsfeil_filters();
    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $totals = np_order_hub_query_produksjonsfeil_totals($filters);
    $rows = np_order_hub_query_produksjonsfeil_rows($filters, 1000);
    $by_store = np_order_hub_query_produksjonsfeil_by_store($filters);
    $products = np_order_hub_query_produksjonsfeil_products($filters);

    $currency_label = '';
    if (!empty($by_store)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $by_store))));
        if (count($currencies) === 1) {
            $currency_label = (string) $currencies[0];
        }
    }

	    $base_url = admin_url('admin.php?page=np-order-hub-produksjonsfeil');
	    $filter_query = array();
	    foreach (array('store', 'date_from', 'date_to', 's') as $key) {
	        if (!empty($_GET[$key])) {
	            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
	        }
	    }
	    $view_options = np_order_hub_get_production_error_type_options();
	    $current_view = np_order_hub_normalize_production_error_type((string) ($filters['error_type'] ?? 'trykkfeil'));
	    $current_view_label = np_order_hub_get_production_error_type_label($current_view);

	    echo '<div class="wrap np-order-hub-produksjonsfeil-page">';
	    echo '<h1>Ødelagt plagg</h1>';
	    echo '<style>
	        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
	        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
	        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
	        .np-order-hub-card-row strong{font-weight:600;}
	    </style>';
	    echo '<h2 class="nav-tab-wrapper" style="margin-bottom:16px;">';
	    foreach ($view_options as $view_key => $view_label) {
	        $view_url_args = $filter_query;
	        $view_url_args['view'] = $view_key;
	        $view_url = add_query_arg($view_url_args, $base_url);
	        $active = $current_view === $view_key ? ' nav-tab-active' : '';
	        echo '<a class="nav-tab' . esc_attr($active) . '" href="' . esc_url($view_url) . '">' . esc_html($view_label) . '</a>';
	    }
	    echo '</h2>';

	    echo '<form method="get" class="np-order-hub-filters">';
	    echo '<input type="hidden" name="page" value="np-order-hub-produksjonsfeil" />';
	    echo '<input type="hidden" name="view" value="' . esc_attr($current_view) . '" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-produksjonsfeil-store">Store</label>';
    echo '<select id="np-order-hub-produksjonsfeil-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-produksjonsfeil-date-from">From</label>';
    echo '<input id="np-order-hub-produksjonsfeil-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-produksjonsfeil-date-to">To</label>';
    echo '<input id="np-order-hub-produksjonsfeil-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-produksjonsfeil-search">Search</label>';
    echo '<input id="np-order-hub-produksjonsfeil-search" type="text" name="s" value="' . esc_attr($filters['search']) . '" placeholder="Produkt, SKU, størrelse..." />';
    echo '</div>';

	    echo '<div class="field">';
	    echo '<button class="button button-primary" type="submit">Filter</button> ';
	    if (!empty($filter_query)) {
	        echo '<a class="button" href="' . esc_url(add_query_arg('view', $current_view, $base_url)) . '">Clear</a>';
	    }
	    echo '</div>';
	    echo '</form>';

	    $total_display = np_order_hub_format_money((float) ($totals['cost_total'] ?? 0), $currency_label);
	    echo '<div class="card" style="max-width:340px; margin:12px 0 16px;">';
	    echo '<h3 style="margin-top:0;">' . esc_html($current_view_label) . ' totalt</h3>';
	    echo '<div class="np-order-hub-card-row"><span>Registreringer</span><strong>' . esc_html((string) ((int) ($totals['rows_count'] ?? 0))) . '</strong></div>';
	    echo '<div class="np-order-hub-card-row"><span>Antall plagg</span><strong>' . esc_html((string) ((int) ($totals['qty_total'] ?? 0))) . '</strong></div>';
	    echo '<div class="np-order-hub-card-row"><span>Kostnad</span><strong>' . esc_html($total_display) . '</strong></div>';
	    echo '</div>';

    echo '<h2>Logg</h2>';
    echo '<table class="widefat striped">';
	    echo '<thead><tr>';
	    echo '<th>Tid</th>';
	    echo '<th>Type</th>';
	    echo '<th>Store</th>';
	    echo '<th>Produkt</th>';
	    echo '<th>Størrelse</th>';
	    echo '<th>SKU</th>';
    echo '<th>Antall</th>';
    echo '<th>Kostnad</th>';
    echo '<th>Lager</th>';
	    echo '<th>Kommentar</th>';
	    echo '</tr></thead>';
	    echo '<tbody>';
	    if (empty($rows)) {
	        echo '<tr><td colspan="10">Ingen ødelagte plagg registrert.</td></tr>';
	    } else {
	        foreach ($rows as $row) {
	            $date_gmt = isset($row['created_at_gmt']) ? (string) $row['created_at_gmt'] : '';
	            $date_label = $date_gmt !== '' ? get_date_from_gmt($date_gmt, 'd.m.y H:i') : '';
	            $type_label = np_order_hub_get_production_error_type_label((string) ($row['error_type'] ?? 'trykkfeil'));
	            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : (string) ($row['store_key'] ?? '');
	            $product_name = isset($row['product_name']) ? (string) $row['product_name'] : '';
	            $size_label = isset($row['size_label']) ? (string) $row['size_label'] : '';
            $sku = isset($row['sku']) ? (string) $row['sku'] : '';
            $qty = isset($row['quantity']) ? (int) $row['quantity'] : 0;
            $cost_display = np_order_hub_format_money((float) ($row['total_cost'] ?? 0), (string) ($row['currency'] ?? ''));
            $note = isset($row['note']) ? (string) $row['note'] : '';
            $stock_before = isset($row['stock_before']) && $row['stock_before'] !== null ? rtrim(rtrim(number_format((float) $row['stock_before'], 2, '.', ''), '0'), '.') : '';
            $stock_after = isset($row['stock_after']) && $row['stock_after'] !== null ? rtrim(rtrim(number_format((float) $row['stock_after'], 2, '.', ''), '0'), '.') : '';
            $stock_label = '—';
            if ($stock_before !== '' || $stock_after !== '') {
                $stock_label = ($stock_before !== '' ? $stock_before : '—') . ' → ' . ($stock_after !== '' ? $stock_after : '—');
            }

	            echo '<tr>';
	            echo '<td>' . esc_html($date_label) . '</td>';
	            echo '<td>' . esc_html($type_label) . '</td>';
	            echo '<td>' . esc_html($store_name) . '</td>';
	            echo '<td>' . esc_html($product_name) . '</td>';
	            echo '<td>' . esc_html($size_label !== '' ? $size_label : '—') . '</td>';
            echo '<td>' . esc_html($sku !== '' ? $sku : '—') . '</td>';
            echo '<td>' . esc_html((string) $qty) . '</td>';
            echo '<td>' . esc_html($cost_display) . '</td>';
            echo '<td>' . esc_html($stock_label) . '</td>';
            echo '<td>' . esc_html($note !== '' ? $note : '—') . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';

    echo '<h2 style="margin-top:16px;">Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Registreringer</th>';
    echo '<th>Antall</th>';
    echo '<th>Kostnad</th>';
    echo '</tr></thead>';
	    echo '<tbody>';
	    if (empty($by_store)) {
	        echo '<tr><td colspan="4">Ingen ødelagte plagg registrert.</td></tr>';
	    } else {
        foreach ($by_store as $row) {
            echo '<tr>';
            echo '<td>' . esc_html((string) ($row['store_name'] ?? $row['store_key'] ?? '')) . '</td>';
            echo '<td>' . esc_html((string) ((int) ($row['rows_count'] ?? 0))) . '</td>';
            echo '<td>' . esc_html((string) ((int) ($row['qty_total'] ?? 0))) . '</td>';
            echo '<td>' . esc_html(np_order_hub_format_money((float) ($row['cost_total'] ?? 0), (string) ($row['currency'] ?? ''))) . '</td>';
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
    echo '<th>Størrelse</th>';
    echo '<th>SKU</th>';
    echo '<th>Antall</th>';
    echo '<th>Kostnad</th>';
    echo '</tr></thead>';
	    echo '<tbody>';
	    if (empty($products)) {
	        echo '<tr><td colspan="6">Ingen ødelagte plagg registrert.</td></tr>';
	    } else {
        foreach ($products as $row) {
            echo '<tr>';
            echo '<td>' . esc_html((string) ($row['store_name'] ?? $row['store_key'] ?? '')) . '</td>';
            echo '<td>' . esc_html((string) ($row['product_name'] ?? '')) . '</td>';
            echo '<td>' . esc_html((string) (($row['size_label'] ?? '') !== '' ? $row['size_label'] : '—')) . '</td>';
            echo '<td>' . esc_html((string) (($row['sku'] ?? '') !== '' ? $row['sku'] : '—')) . '</td>';
            echo '<td>' . esc_html((string) ((int) ($row['qty_total'] ?? 0))) . '</td>';
            echo '<td>' . esc_html(np_order_hub_format_money((float) ($row['cost_total'] ?? 0), (string) ($row['currency'] ?? ''))) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
}