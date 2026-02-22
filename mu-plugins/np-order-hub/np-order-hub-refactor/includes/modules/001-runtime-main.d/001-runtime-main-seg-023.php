<?php
function np_order_hub_revenue_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $stores = np_order_hub_get_stores();
    $store_options = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
        }
    }

    $history_seed = np_order_hub_get_historical_revenue();
    $manual_revenue = np_order_hub_get_manual_revenue();
    $existing_history_keys = array();
    foreach ($history_seed as $key => $value) {
        $key = sanitize_key((string) $key);
        if ($key !== '') {
            $existing_history_keys[$key] = true;
        }
    }
    foreach ($manual_revenue as $key => $value) {
        $key = sanitize_key((string) $key);
        if ($key !== '') {
            $existing_history_keys[$key] = true;
        }
    }
    $importable_store_options = $store_options;
    foreach ($existing_history_keys as $key => $unused) {
        if (isset($importable_store_options[$key])) {
            unset($importable_store_options[$key]);
        }
    }

    $selected_import_stores = array();
    $has_import_selection = isset($_POST['np_order_hub_import_stores']);
    if ($has_import_selection) {
        $selected_import_stores = array_values(array_filter(array_map(function ($value) {
            return sanitize_key((string) $value);
        }, (array) $_POST['np_order_hub_import_stores'])));
        if (!empty($importable_store_options)) {
            $selected_import_stores = array_values(array_intersect($selected_import_stores, array_keys($importable_store_options)));
        }
    } else {
        $selected_import_stores = array_keys($importable_store_options);
    }

    $import_notice = '';
    $import_errors = array();
    if (!empty($_POST['np_order_hub_import_revenue']) && check_admin_referer('np_order_hub_import_revenue')) {
        $history = np_order_hub_get_historical_revenue();
        $skip_history_keys = array();
        foreach ($history as $key => $value) {
            $key = sanitize_key((string) $key);
            if ($key !== '') {
                $skip_history_keys[$key] = true;
            }
        }
        foreach ($manual_revenue as $key => $value) {
            $key = sanitize_key((string) $key);
            if ($key !== '') {
                $skip_history_keys[$key] = true;
            }
        }
        $imported = 0;
        if ($has_import_selection && empty($selected_import_stores)) {
            $import_errors[] = 'Select at least one store to import.';
        }
        foreach ($stores as $store) {
            if (!is_array($store) || empty($store['key'])) {
                continue;
            }
            $store_key = sanitize_key((string) $store['key']);
            if ($has_import_selection && !in_array($store_key, $selected_import_stores, true)) {
                continue;
            }
            if (isset($skip_history_keys[$store_key])) {
                continue;
            }
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_start',
                'store' => isset($store['name']) ? (string) $store['name'] : $store_key,
                'has_api' => !empty($store['consumer_key']) && !empty($store['consumer_secret']),
            ));
            if (empty($store['consumer_key']) || empty($store['consumer_secret'])) {
                $import_errors[] = 'Missing API keys for ' . (isset($store['name']) ? (string) $store['name'] : $store['key']);
                np_order_hub_revenue_debug_add($store_key, array(
                    'event' => 'import_error',
                    'message' => 'Missing API keys.',
                ));
                continue;
            }
            $date_to_gmt = np_order_hub_get_store_first_order_gmt($store_key);
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_date',
                'date_to_gmt' => $date_to_gmt,
            ));
            $result = np_order_hub_fetch_store_sales_total($store, $date_to_gmt);
            if (is_wp_error($result)) {
                $import_errors[] = 'API error for ' . (isset($store['name']) ? (string) $store['name'] : $store['key']) . ': ' . $result->get_error_message();
                np_order_hub_revenue_debug_add($store_key, array(
                    'event' => 'import_error',
                    'message' => $result->get_error_message(),
                ));
                continue;
            }
            $history[$store_key] = array(
                'total' => isset($result['total']) ? (float) $result['total'] : 0.0,
                'count' => isset($result['count']) ? (int) $result['count'] : 0,
                'currency' => isset($store['currency']) ? (string) $store['currency'] : '',
                'date_to_gmt' => $date_to_gmt,
                'updated_at_gmt' => current_time('mysql', true),
            );
            np_order_hub_revenue_debug_add($store_key, array(
                'event' => 'import_ok',
                'total' => isset($result['total']) ? (float) $result['total'] : 0.0,
                'count' => isset($result['count']) ? (int) $result['count'] : 0,
            ));
            $imported++;
        }
        np_order_hub_save_historical_revenue($history);
        if ($imported > 0) {
            $import_notice = 'Historical revenue imported.';
        }
        if ($imported === 0 && empty($import_errors)) {
            if (empty($importable_store_options)) {
                $import_errors[] = 'Alle butikker har allerede historisk omsetning.';
            } else {
                $import_errors[] = 'No stores were imported. Add API credentials first.';
            }
        }
    }

    $filters = np_order_hub_get_revenue_filters();

    $rows = np_order_hub_query_revenue_by_store($filters);
    $totals = np_order_hub_query_revenue_totals($filters);
    $history = np_order_hub_get_historical_revenue();
    if (!empty($manual_revenue)) {
        foreach ($manual_revenue as $store_key => $manual) {
            if (!is_array($manual)) {
                continue;
            }
            $store_key = sanitize_key((string) $store_key);
            if ($store_key === '') {
                continue;
            }
            $history[$store_key] = array(
                'total' => isset($manual['total']) ? (float) $manual['total'] : 0.0,
                'count' => isset($manual['count']) ? (int) $manual['count'] : 0,
                'currency' => isset($manual['currency']) ? (string) $manual['currency'] : '',
                'date_to_gmt' => isset($manual['date_to_gmt']) ? (string) $manual['date_to_gmt'] : '',
                'updated_at_gmt' => isset($manual['updated_at_gmt']) ? (string) $manual['updated_at_gmt'] : current_time('mysql', true),
                'manual' => true,
            );
        }
    }
    $include_history = ($filters['date_from_raw'] === '' && $filters['date_to_raw'] === '');
    $history_total = 0.0;
    $history_count = 0;
    if ($include_history && !empty($history)) {
        $rows_by_key = array();
        foreach ($rows as $row) {
            if (!empty($row['store_key'])) {
                $rows_by_key[(string) $row['store_key']] = $row;
            }
        }
        foreach ($history as $store_key => $hist) {
            $store_key = sanitize_key((string) $store_key);
            if ($store_key === '') {
                continue;
            }
            if (!isset($rows_by_key[$store_key])) {
                $rows_by_key[$store_key] = array(
                    'store_key' => $store_key,
                    'store_name' => isset($store_options[$store_key]) ? $store_options[$store_key] : $store_key,
                    'currency' => isset($hist['currency']) ? (string) $hist['currency'] : '',
                    'count' => 0,
                    'total' => 0.0,
                );
            }
            $hist_total = isset($hist['total']) ? (float) $hist['total'] : 0.0;
            $hist_count = isset($hist['count']) ? (int) $hist['count'] : 0;
            $rows_by_key[$store_key]['total'] = (float) $rows_by_key[$store_key]['total'] + $hist_total;
            $rows_by_key[$store_key]['count'] = (int) $rows_by_key[$store_key]['count'] + $hist_count;
            $history_total += $hist_total;
            $history_count += $hist_count;
        }
        $rows = array_values($rows_by_key);
        $totals['total'] = (float) $totals['total'] + $history_total;
        $totals['count'] = (int) $totals['count'] + $history_count;
    }
    if (!empty($rows)) {
        usort($rows, function ($a, $b) {
            $store_cmp = strcmp((string) ($a['store_name'] ?? ''), (string) ($b['store_name'] ?? ''));
            if ($store_cmp !== 0) {
                return $store_cmp;
            }
            return strcmp((string) ($a['store_key'] ?? ''), (string) ($b['store_key'] ?? ''));
        });
    }

    $currency_label = '';
    $has_multiple_currencies = false;
    if (!empty($rows)) {
        $currencies = array_values(array_unique(array_filter(array_map(function ($row) {
            return isset($row['currency']) ? (string) $row['currency'] : '';
        }, $rows))));
        $currency_count = count($currencies);
        if ($currency_count === 1) {
            $currency_label = (string) $currencies[0];
        }
        $has_multiple_currencies = $currency_count > 1;
    }

    $vat_rate = np_order_hub_get_vat_rate();
    $totals_split = np_order_hub_split_amount_with_vat((float) $totals['total'], $vat_rate);
    $vat_mode_input = isset($_GET['np_vat_mode']) ? sanitize_key((string) wp_unslash($_GET['np_vat_mode'])) : 'ex';
    $vat_mode = $vat_mode_input === 'inc' ? 'inc' : 'ex';
    $is_inc_mode = $vat_mode === 'inc';
    $selected_mode_label = $is_inc_mode ? 'inkl mva' : 'eks mva';
    $total_ex_display = np_order_hub_format_money((float) $totals_split['net'], $currency_label);
    $total_inc_display = np_order_hub_format_money((float) $totals_split['gross'], $currency_label);
    $selected_total_display = $is_inc_mode ? $total_inc_display : $total_ex_display;
    $count = isset($totals['count']) ? (int) $totals['count'] : 0;

    $base_url = admin_url('admin.php?page=np-order-hub-revenue');
    $filter_query = array();
    foreach (array('store', 'date_from', 'date_to', 'np_vat_mode') as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    echo '<div class="wrap np-order-hub-revenue-page">';
    echo '<h1>Omsetning</h1>';
    if ($import_notice !== '') {
        echo '<div class="updated"><p>' . esc_html($import_notice) . '</p></div>';
    }
    if (!empty($import_errors)) {
        foreach ($import_errors as $error) {
            echo '<div class="error"><p>' . esc_html($error) . '</p></div>';
        }
    }
    echo '<style>
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
        .np-order-hub-import-stores{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 16px;margin-top:8px;}
        .np-order-hub-import-stores label{display:flex;align-items:center;gap:8px;}
        .np-order-hub-import-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;}
        .np-order-hub-debug{margin:16px 0;padding:12px;border:1px solid #dcdcde;background:#fff;}
        .np-order-hub-debug summary{cursor:pointer;font-weight:600;}
        .np-order-hub-debug pre{white-space:pre-wrap;margin:8px 0 0;max-height:320px;overflow:auto;background:#f6f7f7;padding:8px;border:1px solid #dcdcde;}
    </style>';

    echo '<form method="post" style="margin:12px 0 8px;">';
    wp_nonce_field('np_order_hub_import_revenue');
    echo '<div>';
    echo '<button class="button" type="submit" name="np_order_hub_import_revenue" value="1">Import historical revenue</button>';
    echo ' <label style="margin-left:8px;"><input type="checkbox" name="np_order_hub_import_debug" value="1"' . (!empty($_POST['np_order_hub_import_debug']) ? ' checked' : '') . '> Debug</label>';
    echo '</div>';
    echo '<p class="description" style="margin-top:8px;">Velg hvilke butikker som skal importeres. Bruker WooCommerce API og henter omsetning før første ordre mottatt i huben.</p>';
    if (!empty($importable_store_options)) {
        echo '<div class="np-order-hub-import-actions">';
        echo '<button type="button" class="button" id="np-order-hub-import-select-all">Velg alle</button>';
        echo '<button type="button" class="button" id="np-order-hub-import-clear-all">Fjern alle</button>';
        echo '</div>';
        echo '<div class="np-order-hub-import-stores">';
        foreach ($importable_store_options as $key => $label) {
            $checked = in_array($key, $selected_import_stores, true) ? ' checked' : '';
            echo '<label><input type="checkbox" name="np_order_hub_import_stores[]" value="' . esc_attr($key) . '"' . $checked . '> ' . esc_html($label) . '</label>';
        }
        echo '</div>';
    } else {
        echo '<p class="description" style="margin-top:8px;">Alle butikker har allerede historisk omsetning.</p>';
    }
    echo '</form>';

    if (np_order_hub_revenue_debug_enabled()) {
        $debug = np_order_hub_revenue_debug_get();
        if (!empty($debug)) {
            echo '<details class="np-order-hub-debug" open>';
            echo '<summary>Import debug</summary>';
            foreach ($debug as $store_key => $entries) {
                $title = isset($store_options[$store_key]) ? $store_options[$store_key] : $store_key;
                echo '<h4 style="margin:10px 0 4px;">' . esc_html($title) . '</h4>';
                echo '<pre>' . esc_html(wp_json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
            }
            echo '</details>';
        }
    }

    if (!empty($importable_store_options)) {
        echo '<script>
            (function(){
                var selectAll = document.getElementById("np-order-hub-import-select-all");
                var clearAll = document.getElementById("np-order-hub-import-clear-all");
                var boxes = document.querySelectorAll("input[name=\'np_order_hub_import_stores[]\']");
                if (selectAll) {
                    selectAll.addEventListener("click", function(){
                        boxes.forEach(function(box){ box.checked = true; });
                    });
                }
                if (clearAll) {
                    clearAll.addEventListener("click", function(){
                        boxes.forEach(function(box){ box.checked = false; });
                    });
                }
            })();
        </script>';
    }

    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="np-order-hub-revenue" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-store">Store</label>';
    echo '<select id="np-order-hub-revenue-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-date-from">From</label>';
    echo '<input id="np-order-hub-revenue-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-date-to">To</label>';
    echo '<input id="np-order-hub-revenue-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-revenue-vat-mode">Omsetning</label>';
    echo '<select id="np-order-hub-revenue-vat-mode" name="np_vat_mode">';
    echo '<option value="ex"' . selected($vat_mode, 'ex', false) . '>Eks mva</option>';
    echo '<option value="inc"' . selected($vat_mode, 'inc', false) . '>Inkl mva</option>';
    echo '</select>';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($base_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    echo '<div class="card" style="max-width:320px; margin:12px 0 16px;">';
    echo '<h3 style="margin-top:0;">Omsetning totalt</h3>';
    echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
    echo '<div class="np-order-hub-card-row"><span>Omsetning</span><strong>' . esc_html($selected_total_display) . '</strong></div>';
    echo '<p class="description" style="margin-top:8px;">Viser ' . esc_html($selected_mode_label) . '.</p>';
    if (!$include_history && !empty($history)) {
        echo '<p class="description" style="margin-top:8px;">Historisk omsetning er skjult når du bruker datofilter.</p>';
    } elseif ($include_history && !empty($history)) {
        $history_split = np_order_hub_split_amount_with_vat($history_total, $vat_rate);
        $history_value = $is_inc_mode ? (float) $history_split['gross'] : (float) $history_split['net'];
        $history_display = np_order_hub_format_money($history_value, $currency_label);
        echo '<div class="np-order-hub-card-row"><span>Historisk</span><strong>' . esc_html($history_display) . '</strong></div>';
    }
    if ($has_multiple_currencies) {
        echo '<p class="description" style="margin-top:8px;">Flere valutaer i resultatet.</p>';
    }
    echo '</div>';

    echo '<h2>Per butikk</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Orders</th>';
    echo '<th>Omsetning</th>';
    echo '</tr></thead>';
    echo '<tbody>';
    if (empty($rows)) {
        echo '<tr><td colspan="3">Ingen ordre funnet.</td></tr>';
    } else {
        foreach ($rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $store_key = isset($row['store_key']) ? sanitize_key((string) $row['store_key']) : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_split = np_order_hub_split_amount_with_vat($row_total, $vat_rate);
            $row_selected_value = $is_inc_mode ? (float) $row_split['gross'] : (float) $row_split['net'];
            $row_revenue_display = np_order_hub_format_money($row_selected_value, $row_currency);
            $store_data = $store_key !== '' ? np_order_hub_get_store_by_key($store_key) : null;
            $store_orders_url = is_array($store_data) ? np_order_hub_build_admin_orders_url($store_data) : '';
            if ($store_orders_url === '' && $store_key !== '') {
                $store_orders_url = add_query_arg(array(
                    'page' => 'np-order-hub',
                    'store' => $store_key,
                ), admin_url('admin.php'));
            }
            $store_label = $store_name !== '' ? $store_name : $store_key;

            echo '<tr>';
	            echo '<td>';
	            if ($store_orders_url !== '') {
	                echo '<a href="' . esc_url($store_orders_url) . '" target="_blank" rel="noopener">' . esc_html($store_label) . '</a>';
	            } else {
	                echo esc_html($store_label);
	            }
            echo '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html($row_revenue_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
}