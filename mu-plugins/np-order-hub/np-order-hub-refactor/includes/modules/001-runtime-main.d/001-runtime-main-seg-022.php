<?php
function np_order_hub_create_remote_reklamasjon_order($store, $order_id, $items, $allow_oos = false) {
    $order_id = (int) $order_id;
    if ($order_id < 1 || empty($items) || !is_array($items)) {
        return new WP_Error('missing_params', 'Missing order ID or items.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_token', 'Store token missing.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'reklamasjon-order');
    if ($endpoint === '') {
        return new WP_Error('missing_endpoint', 'Store endpoint missing.');
    }

    $response = wp_remote_post($endpoint, array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ),
        'body' => wp_json_encode(array(
            'order_id' => $order_id,
            'items' => array_values($items),
            'allow_oos' => $allow_oos ? true : false,
            'token' => $token,
        )),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        $message = 'Claim order creation failed.';
        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (is_array($decoded) && !empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            }
        }
        $error_code = $code === 409 ? 'stock_unavailable' : 'claim_order_failed';
        return new WP_Error($error_code, $message, array(
            'status' => $code,
            'body' => $body,
        ));
    }

    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (is_array($decoded)) {
        return $decoded;
    }
    return array('status' => 'ok');
}

function np_order_hub_apply_local_status($record, $status) {
    if (!is_array($record) || empty($record['id'])) {
        return $record;
    }
    global $wpdb;
    $table = np_order_hub_table_name();

    $update = array(
        'status' => $status,
        'updated_at_gmt' => current_time('mysql', true),
    );
    if (!empty($record['payload'])) {
        $decoded = json_decode($record['payload'], true);
        if (is_array($decoded)) {
            $decoded['status'] = $status;
            $update['payload'] = wp_json_encode($decoded);
        }
    }
    $wpdb->update($table, $update, array('id' => (int) $record['id']));

    $record['status'] = $status;
    if (!empty($update['payload'])) {
        $record['payload'] = $update['payload'];
    }
    return $record;
}

function np_order_hub_dashboard_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $page_slug = isset($_GET['page']) ? sanitize_key((string) $_GET['page']) : 'np-order-hub-dashboard';
    $delivery_bucket = $page_slug === 'np-order-hub-scheduled' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
    $dashboard_title = $delivery_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
    $default_status = 'processing';
    $show_status_filter = true;
    $show_status_tabs = true;
    $show_reklamasjon = $delivery_bucket !== NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED;

    $bulk_notice = null;
    if (!empty($_POST['np_order_hub_bulk_action'])) {
        check_admin_referer('np_order_hub_bulk_action');
        $action = sanitize_key((string) $_POST['np_order_hub_bulk_action']);
        $bulk_status = sanitize_key((string) ($_POST['bulk_status'] ?? ''));
        $record_ids = isset($_POST['order_ids']) ? array_map('absint', (array) $_POST['order_ids']) : array();
        $record_ids = array_filter($record_ids, function ($value) {
            return $value > 0;
        });

        $allowed_actions = array('packing_slips', 'update_status', 'delete_from_hub', 'mark_scheduled', 'mark_standard');
        if (!in_array($action, $allowed_actions, true)) {
            $bulk_notice = array('type' => 'error', 'message' => 'Unknown bulk action.');
        } elseif (empty($record_ids)) {
            $bulk_notice = array('type' => 'error', 'message' => 'Select at least one order.');
        } else {
            global $wpdb;
            $table = np_order_hub_table_name();
            $placeholders = implode(',', array_fill(0, count($record_ids), '%d'));
            $records = $wpdb->get_results(
                $wpdb->prepare("SELECT * FROM $table WHERE id IN ($placeholders)", $record_ids),
                ARRAY_A
            );

            if (empty($records)) {
                $bulk_notice = array('type' => 'error', 'message' => 'Orders not found.');
            } elseif ($action === 'delete_from_hub') {
                $deleted = $wpdb->query(
                    $wpdb->prepare("DELETE FROM $table WHERE id IN ($placeholders)", $record_ids)
                );
                if ($deleted === false) {
                    $bulk_notice = array('type' => 'error', 'message' => 'Failed to delete orders.');
                } elseif ($deleted < 1) {
                    $bulk_notice = array('type' => 'error', 'message' => 'No orders were deleted.');
                } else {
                    $bulk_notice = array('type' => 'success', 'message' => 'Deleted ' . $deleted . ' orders from hub.');
                }
            } elseif (in_array($action, array('mark_scheduled', 'mark_standard'), true)) {
                $target_bucket = $action === 'mark_scheduled' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
                $updated = 0;
                foreach ($records as $record) {
                    np_order_hub_update_delivery_bucket($record, $target_bucket);
                    $updated++;
                }
                if ($updated < 1) {
                    $bulk_notice = array('type' => 'error', 'message' => 'No orders were updated.');
                } else {
                    $label = $target_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
                    $bulk_notice = array('type' => 'success', 'message' => 'Moved ' . $updated . ' orders to ' . $label . '.');
                }
            } else {
                $store_keys = array_values(array_unique(array_filter(array_map(function ($row) {
                    return isset($row['store_key']) ? (string) $row['store_key'] : '';
                }, $records))));

                if ($action === 'packing_slips') {
                    if (count($store_keys) === 1) {
                        $store = np_order_hub_get_store_by_key($store_keys[0]);
                        $order_ids = array_map(function ($row) {
                            return isset($row['order_id']) ? (int) $row['order_id'] : 0;
                        }, $records);
                        $order_ids = array_filter($order_ids, function ($value) {
                            return $value > 0;
                        });
                        $bulk_url = np_order_hub_build_packing_slips_url($store, $order_ids);
                        if ($bulk_url === '') {
                            $bulk_notice = array('type' => 'error', 'message' => 'Packing slip bulk URL is not configured for this store.');
                        } else {
                            wp_redirect($bulk_url);
                            exit;
                        }
                    } else {
                        $groups = array();
                        $missing_stores = array();
                        foreach ($records as $record) {
                            $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
                            $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
                            if ($store_key === '' || $order_id < 1) {
                                continue;
                            }
                            if (!isset($groups[$store_key])) {
                                $store = np_order_hub_get_store_by_key($store_key);
                                if (!$store) {
                                    $missing_stores[$store_key] = true;
                                    continue;
                                }
                                $groups[$store_key] = array(
                                    'store' => $store,
                                    'order_ids' => array(),
                                );
                            }
                            if (isset($groups[$store_key])) {
                                $groups[$store_key]['order_ids'][] = $order_id;
                            }
                        }

                        if (!empty($missing_stores)) {
                            $bulk_notice = array(
                                'type' => 'error',
                                'message' => 'Stores not found: ' . implode(', ', array_keys($missing_stores)) . '.',
                            );
                        } elseif (empty($groups)) {
                            $bulk_notice = array('type' => 'error', 'message' => 'Orders not found.');
                        } else {
                            $bundle = np_order_hub_build_packing_slips_bundle($groups);
                            if (is_wp_error($bundle)) {
                                $bulk_notice = array('type' => 'error', 'message' => $bundle->get_error_message());
                            } elseif (!empty($bundle['preview_links'])) {
                                $merge_error = isset($bundle['merge_error']) ? (string) $bundle['merge_error'] : '';
                                np_order_hub_send_packing_slips_preview_page($bundle['preview_links'], $merge_error);
                                exit;
                            } else {
                                np_order_hub_send_download($bundle);
                                exit;
                            }
                        }
                    }
                } else {
                    $allowed_statuses = np_order_hub_get_allowed_statuses();
                    if (empty($bulk_status) || !isset($allowed_statuses[$bulk_status])) {
                        $bulk_notice = array('type' => 'error', 'message' => 'Select a valid status for bulk update.');
                    } else {
                        $updated = 0;
                        $failed = 0;
                        $first_error = '';
                        $missing_stores = array();
                        $missing_tokens = array();
                        $store_cache = array();

                        foreach ($records as $record) {
                            $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
                            $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
                            if ($order_id < 1 || $store_key === '') {
                                $failed++;
                                continue;
                            }

                            if (!array_key_exists($store_key, $store_cache)) {
                                $store_cache[$store_key] = np_order_hub_get_store_by_key($store_key);
                            }
                            $store = $store_cache[$store_key];
                            if (!$store) {
                                $missing_stores[$store_key] = true;
                                $failed++;
                                continue;
                            }

                            $token = np_order_hub_get_store_token($store);
                            if ($token === '') {
                                $missing_tokens[$store_key] = true;
                                $failed++;
                                continue;
                            }

                            $result = np_order_hub_update_remote_order_status($store, $order_id, $bulk_status);
                            if (is_wp_error($result)) {
                                $failed++;
                                if ($first_error === '') {
                                    $first_error = $result->get_error_message();
                                }
                                continue;
                            }
                            np_order_hub_apply_local_status($record, $bulk_status);
                            $updated++;
                        }

                        if ($updated > 0 && $failed === 0) {
                            $bulk_notice = array('type' => 'success', 'message' => 'Updated ' . $updated . ' orders.');
                        } else {
                            $message = $updated > 0
                                ? 'Updated ' . $updated . ' orders, ' . $failed . ' failed.'
                                : 'No orders were updated.';
                            if (!empty($missing_stores)) {
                                $message .= ' Missing stores: ' . implode(', ', array_keys($missing_stores)) . '.';
                            }
                            if (!empty($missing_tokens)) {
                                $message .= ' Missing store tokens: ' . implode(', ', array_keys($missing_tokens)) . '.';
                            }
                            if ($first_error !== '') {
                                $message .= ' First error: ' . $first_error;
                            }
                            $bulk_notice = array('type' => 'error', 'message' => $message);
                        }
                    }
                }
            }
        }
    }

    $filters = np_order_hub_get_dashboard_filters($default_status);
    $processing_count = np_order_hub_get_processing_count_for_bucket(
        $delivery_bucket,
        isset($filters['store']) ? (string) $filters['store'] : ''
    );
    $metric_filters = array(
        'store' => $filters['store'],
        'status' => $filters['status'],
    );

    $currency_label = np_order_hub_get_currency_label($metric_filters, $delivery_bucket);
    $now_gmt = current_time('timestamp', true);
    $today_local = current_time('Y-m-d');
    $today_start = get_gmt_from_date($today_local . ' 00:00:00');
    $today_end = get_gmt_from_date($today_local . ' 23:59:59');

    $metrics = array(
        array(
            'label' => 'Today',
            'data' => np_order_hub_query_metric_range($metric_filters, $today_start, $today_end, $delivery_bucket),
        ),
        array(
            'label' => 'Last 7 days',
            'data' => np_order_hub_query_metric_range($metric_filters, gmdate('Y-m-d H:i:s', $now_gmt - (7 * DAY_IN_SECONDS)), gmdate('Y-m-d H:i:s', $now_gmt), $delivery_bucket),
        ),
        array(
            'label' => 'Last 30 days',
            'data' => np_order_hub_query_metric_range($metric_filters, gmdate('Y-m-d H:i:s', $now_gmt - (30 * DAY_IN_SECONDS)), gmdate('Y-m-d H:i:s', $now_gmt), $delivery_bucket),
        ),
        array(
            'label' => 'All time',
            'data' => np_order_hub_query_metric_range($metric_filters, '', '', $delivery_bucket),
        ),
    );

    $reklamasjon_rows = array();
    $reklamasjon_totals = array('count' => 0, 'total' => 0.0);
    $reklamasjon_currency = '';
    if ($show_reklamasjon) {
        $reklamasjon_filters = array(
            'date_from' => $filters['date_from'],
            'date_to' => $filters['date_to'],
        );
        $reklamasjon_rows = np_order_hub_query_reklamasjon_by_store($reklamasjon_filters);
        $reklamasjon_totals = np_order_hub_query_reklamasjon_totals(
            array(),
            $filters['date_from'],
            $filters['date_to']
        );
        if (!empty($reklamasjon_rows)) {
            $reklamasjon_currencies = array_values(array_unique(array_filter(array_map(function ($row) {
                return isset($row['currency']) ? (string) $row['currency'] : '';
            }, $reklamasjon_rows))));
            if (count($reklamasjon_currencies) === 1) {
                $reklamasjon_currency = (string) $reklamasjon_currencies[0];
            }
        }
    }

    $per_page = NP_ORDER_HUB_PER_PAGE;
    $current_page = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1;
    $offset = ($current_page - 1) * $per_page;
    $total_items = 0;
    $orders = np_order_hub_query_orders($filters, $per_page, $offset, $total_items, $delivery_bucket);
    $total_pages = $per_page > 0 ? (int) ceil($total_items / $per_page) : 1;

    $stores = np_order_hub_get_stores();
    $store_options = array();
    $store_currency_map = array();
    foreach ($stores as $store) {
        if (is_array($store) && !empty($store['key']) && !empty($store['name'])) {
            $store_options[$store['key']] = $store['name'];
            if (!empty($store['currency'])) {
                $store_currency_map[$store['key']] = (string) $store['currency'];
            }
        }
    }
    $statuses = array();
    if ($show_status_filter) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $status_args = array();
        $status_filters = array('store' => $filters['store']);
        $status_where = np_order_hub_build_where_clause($status_filters, $status_args, false, false);
        $status_sql = "SELECT DISTINCT status FROM $table $status_where ORDER BY status";
        $status_rows = $status_args ? $wpdb->get_col($wpdb->prepare($status_sql, $status_args)) : $wpdb->get_col($status_sql);
        foreach ((array) $status_rows as $status) {
            $status = sanitize_key((string) $status);
            if ($status !== '') {
                $statuses[$status] = ucwords(str_replace('-', ' ', $status));
            }
        }
    }

    $base_url = admin_url('admin.php?page=' . ($delivery_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'np-order-hub-scheduled' : 'np-order-hub-dashboard'));
    $clear_url = $base_url;
    $filter_query = array();
    $filter_keys = array('store', 'date_from', 'date_to', 's');
    if ($show_status_filter) {
        $filter_keys[] = 'status';
    }
    foreach ($filter_keys as $key) {
        if (!empty($_GET[$key])) {
            $filter_query[$key] = sanitize_text_field((string) $_GET[$key]);
        }
    }

    $status_tabs = array(
        '' => 'All',
        'processing' => 'Processing',
        'restordre' => 'Restordre',
        'bytte-storrelse' => 'Bytte størrelse',
        'on-hold' => 'On hold',
        'completed' => 'Completed',
    );

    echo '<div class="wrap np-order-hub-dashboard">';
    if (!empty($bulk_notice) && is_array($bulk_notice)) {
        $type = $bulk_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($bulk_notice['message']) ? (string) $bulk_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }
    echo '<h1>' . esc_html($dashboard_title) . '</h1>';
    $processing_label = isset($filters['store']) && $filters['store'] !== ''
        ? 'Processing i denne mappa (valgt butikk): '
        : 'Processing i denne mappa: ';
    echo '<p class="description" style="margin-top:-6px;margin-bottom:12px;"><strong>' . esc_html($processing_label . (string) $processing_count) . '</strong></p>';
    echo '<style>
        .np-order-hub-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:16px 0 24px;}
        .np-order-hub-card{padding:16px;}
        .np-order-hub-card h3{margin:0 0 8px;font-size:14px;font-weight:600;}
        .np-order-hub-card-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-top:4px;}
        .np-order-hub-card-row strong{font-weight:600;}
        .np-order-hub-filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:0 0 16px;}
        .np-order-hub-filters .field{display:flex;flex-direction:column;gap:4px;}
        .np-order-hub-status{display:inline-block;padding:2px 8px;border-radius:12px;background:#f0f0f1;font-size:12px;}
        .np-order-hub-actions .button{margin-right:6px;}
        .np-order-hub-pagination{margin-top:16px;}
        .np-order-hub-pagination .tablenav{padding:0;}
        .np-order-hub-reklamasjon{margin:24px 0;}
        .np-order-hub-reklamasjon .card{max-width:320px;}
        .np-order-hub-reklamasjon table{margin-top:12px;}
        .np-order-hub-status-tabs{margin:16px 0 8px;}
    </style>';

    echo '<div class="np-order-hub-cards">';
    foreach ($metrics as $metric) {
        $count = isset($metric['data']['count']) ? (int) $metric['data']['count'] : 0;
        $total = isset($metric['data']['total']) ? (float) $metric['data']['total'] : 0.0;
        $total_display = np_order_hub_format_money($total, $currency_label);
        echo '<div class="card np-order-hub-card">';
        echo '<h3>' . esc_html($metric['label']) . '</h3>';
        echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $count) . '</strong></div>';
        echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($total_display) . '</strong></div>';
        echo '</div>';
    }
    echo '</div>';

    if ($show_reklamasjon) {
        echo '<div class="np-order-hub-reklamasjon">';
        echo '<h2>Reklamasjon oversikt</h2>';
        if ($filters['date_from'] !== '' || $filters['date_to'] !== '') {
            echo '<p class="description">Bruker valgt datoperiode.</p>';
        }
        $reklamasjon_total_display = np_order_hub_format_money(
            isset($reklamasjon_totals['total']) ? (float) $reklamasjon_totals['total'] : 0.0,
            $reklamasjon_currency
        );
        $reklamasjon_count = isset($reklamasjon_totals['count']) ? (int) $reklamasjon_totals['count'] : 0;
        echo '<div class="card np-order-hub-card">';
        echo '<h3>Reklamasjon totalt</h3>';
        echo '<div class="np-order-hub-card-row"><span>Orders</span><strong>' . esc_html((string) $reklamasjon_count) . '</strong></div>';
        echo '<div class="np-order-hub-card-row"><span>Total</span><strong>' . esc_html($reklamasjon_total_display) . '</strong></div>';
        echo '</div>';

        echo '</div>';
    }

    if ($show_status_tabs) {
        echo '<h2 class="nav-tab-wrapper np-order-hub-status-tabs">';
        foreach ($status_tabs as $status_key => $status_label) {
            $tab_query = $filter_query;
            if ($status_key === '') {
                $tab_query['status'] = 'all';
            } else {
                $tab_query['status'] = $status_key;
            }
            $tab_url = add_query_arg($tab_query, $base_url);
            $active = $filters['status'] === $status_key ? ' nav-tab-active' : '';
            echo '<a class="nav-tab' . esc_attr($active) . '" href="' . esc_url($tab_url) . '">' . esc_html($status_label) . '</a>';
        }
        echo '</h2>';
    }

    echo '<form method="get" class="np-order-hub-filters">';
    echo '<input type="hidden" name="page" value="' . esc_attr($page_slug) . '" />';

    echo '<div class="field">';
    echo '<label for="np-order-hub-store">Store</label>';
    echo '<select id="np-order-hub-store" name="store">';
    echo '<option value="">All stores</option>';
    foreach ($store_options as $key => $label) {
        $selected = $filters['store'] === $key ? ' selected' : '';
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '</div>';

    if ($show_status_filter) {
        echo '<div class="field">';
        echo '<label for="np-order-hub-status">Status</label>';
        echo '<select id="np-order-hub-status" name="status">';
        echo '<option value="">All statuses</option>';
        foreach ($statuses as $key => $label) {
            $selected = $filters['status'] === $key ? ' selected' : '';
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        echo '</div>';
    }

    echo '<div class="field">';
    echo '<label for="np-order-hub-date-from">From</label>';
    echo '<input id="np-order-hub-date-from" type="date" name="date_from" value="' . esc_attr($filters['date_from_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-date-to">To</label>';
    echo '<input id="np-order-hub-date-to" type="date" name="date_to" value="' . esc_attr($filters['date_to_raw']) . '" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<label for="np-order-hub-search">Search</label>';
    echo '<input id="np-order-hub-search" type="search" name="s" value="' . esc_attr($filters['search']) . '" placeholder="Order number or ID" />';
    echo '</div>';

    echo '<div class="field">';
    echo '<button class="button button-primary" type="submit">Filter</button> ';
    if (!empty($filter_query)) {
        echo '<a class="button" href="' . esc_url($clear_url) . '">Clear</a>';
    }
    echo '</div>';
    echo '</form>';

    $bulk_action_url = add_query_arg($filter_query, $base_url);
    echo '<form method="post" class="np-order-hub-bulk" action="' . esc_url($bulk_action_url) . '">';
    wp_nonce_field('np_order_hub_bulk_action');
    echo '<div class="tablenav top">';
    echo '<div class="alignleft actions">';
    echo '<label class="screen-reader-text" for="np-order-hub-bulk-action">Bulk actions</label>';
    echo '<select id="np-order-hub-bulk-action" name="np_order_hub_bulk_action">';
    echo '<option value="">Bulk actions</option>';
    echo '<option value="packing_slips">Download packing slips</option>';
    echo '<option value="update_status">Update status</option>';
    echo '<option value="mark_scheduled">Move to Levering til bestemt dato</option>';
    echo '<option value="mark_standard">Move to Levering 3-5 dager</option>';
    echo '<option value="delete_from_hub">Delete from hub</option>';
    echo '</select>';
    echo '<label class="screen-reader-text" for="np-order-hub-bulk-status">Bulk status</label>';
    echo '<select id="np-order-hub-bulk-status" name="bulk_status">';
    echo '<option value="">Select status</option>';
    foreach (np_order_hub_get_allowed_statuses() as $key => $label) {
        echo '<option value="' . esc_attr($key) . '">' . esc_html($label) . '</option>';
    }
    echo '</select>';
    echo '<button class="button" type="submit">Apply</button>';
    echo '</div>';
    echo '</div>';

    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th class="check-column"><input type="checkbox" id="np-order-hub-select-all" /></th>';
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
        echo '<tr><td colspan="9">No orders found.</td></tr>';
    } else {
        foreach ($orders as $order) {
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
            echo '<td class="check-column"><input type="checkbox" name="order_ids[]" value="' . esc_attr((string) $order['id']) . '" /></td>';
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
    echo '</form>';

    if ($total_pages > 1) {
        $pagination_base = add_query_arg($filter_query, $base_url);
        $pagination_links = paginate_links(array(
            'base' => add_query_arg('paged', '%#%', $pagination_base),
            'format' => '',
            'current' => $current_page,
            'total' => $total_pages,
            'prev_text' => '&laquo;',
            'next_text' => '&raquo;',
        ));
        if ($pagination_links) {
            echo '<div class="np-order-hub-pagination">';
            echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post($pagination_links) . '</div></div>';
            echo '</div>';
        }
    }

    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var selectAll = document.getElementById("np-order-hub-select-all");
            if (selectAll) {
                selectAll.addEventListener("change", function() {
                    var boxes = document.querySelectorAll(".np-order-hub-bulk input[name=\'order_ids[]\']");
                    boxes.forEach(function(box) {
                        box.checked = selectAll.checked;
                    });
                });
            }

            var bulkAction = document.getElementById("np-order-hub-bulk-action");
            var bulkStatus = document.getElementById("np-order-hub-bulk-status");
            var toggleBulkStatus = function() {
                if (!bulkStatus || !bulkAction) {
                    return;
                }
                bulkStatus.disabled = bulkAction.value !== "update_status";
            };
            if (bulkAction && bulkStatus) {
                toggleBulkStatus();
                bulkAction.addEventListener("change", toggleBulkStatus);
            }

            var bulkForm = document.querySelector(".np-order-hub-bulk");
            if (bulkForm && bulkAction) {
                bulkForm.addEventListener("submit", function(event) {
                    if (bulkAction.value === "delete_from_hub") {
                        if (!window.confirm("Delete selected orders from hub?")) {
                            event.preventDefault();
                        }
                    }
                });
            }
        });
    </script>';

    echo '</div>';
}
