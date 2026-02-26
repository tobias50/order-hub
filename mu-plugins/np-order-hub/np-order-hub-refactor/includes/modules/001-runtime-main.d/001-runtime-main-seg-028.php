<?php
if (!defined('NP_ORDER_HUB_DELETED_SYNC_EVENT')) {
    define('NP_ORDER_HUB_DELETED_SYNC_EVENT', 'np_order_hub_sync_deleted_orders_cron');
}
if (!defined('NP_ORDER_HUB_DELETED_SYNC_INTERVAL')) {
    define('NP_ORDER_HUB_DELETED_SYNC_INTERVAL', 300);
}
if (!defined('NP_ORDER_HUB_DELETED_SYNC_LIMIT')) {
    define('NP_ORDER_HUB_DELETED_SYNC_LIMIT', 1000);
}
if (!defined('NP_ORDER_HUB_STATUS_SYNC_EVENT')) {
    define('NP_ORDER_HUB_STATUS_SYNC_EVENT', 'np_order_hub_sync_order_statuses_cron');
}
if (!defined('NP_ORDER_HUB_STATUS_SYNC_LIMIT')) {
    define('NP_ORDER_HUB_STATUS_SYNC_LIMIT', 250);
}
if (!defined('NP_ORDER_HUB_STATUS_SYNC_CURSOR_OPTION')) {
    define('NP_ORDER_HUB_STATUS_SYNC_CURSOR_OPTION', 'np_order_hub_status_sync_cursor');
}

add_filter('cron_schedules', 'np_order_hub_deleted_sync_cron_schedules');
add_action('init', 'np_order_hub_deleted_sync_schedule_event');
add_action(NP_ORDER_HUB_DELETED_SYNC_EVENT, 'np_order_hub_deleted_sync_run_cron');
add_action('init', 'np_order_hub_status_sync_schedule_event');
add_action(NP_ORDER_HUB_STATUS_SYNC_EVENT, 'np_order_hub_status_sync_run_cron');

function np_order_hub_deleted_sync_cron_schedules($schedules) {
    if (!is_array($schedules)) {
        $schedules = array();
    }
    if (empty($schedules['np_order_hub_5min'])) {
        $schedules['np_order_hub_5min'] = array(
            'interval' => NP_ORDER_HUB_DELETED_SYNC_INTERVAL,
            'display' => 'Every 5 minutes (Order Hub deleted-order sync)',
        );
    }
    return $schedules;
}

function np_order_hub_deleted_sync_schedule_event() {
    if (!function_exists('wp_next_scheduled') || !function_exists('wp_schedule_event')) {
        return;
    }
    if (!wp_next_scheduled(NP_ORDER_HUB_DELETED_SYNC_EVENT)) {
        wp_schedule_event(time() + 120, 'np_order_hub_5min', NP_ORDER_HUB_DELETED_SYNC_EVENT);
    }
}

function np_order_hub_deleted_sync_run_cron() {
    np_order_hub_sync_deleted_orders(NP_ORDER_HUB_DELETED_SYNC_LIMIT);
}

function np_order_hub_status_sync_schedule_event() {
    if (!function_exists('wp_next_scheduled') || !function_exists('wp_schedule_event')) {
        return;
    }
    if (!wp_next_scheduled(NP_ORDER_HUB_STATUS_SYNC_EVENT)) {
        wp_schedule_event(time() + 180, 'np_order_hub_5min', NP_ORDER_HUB_STATUS_SYNC_EVENT);
    }
}

function np_order_hub_status_sync_run_cron() {
    np_order_hub_sync_order_statuses(NP_ORDER_HUB_STATUS_SYNC_LIMIT);
}

function np_order_hub_wc_response_indicates_missing_order($status_code, $body) {
    $status_code = (int) $status_code;
    if ($status_code === 404 || $status_code === 410) {
        return true;
    }

    if (!is_string($body) || $body === '') {
        return false;
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return false;
    }

    $code = isset($decoded['code']) ? sanitize_key((string) $decoded['code']) : '';
    if ($code === '') {
        return false;
    }

    if (strpos($code, 'invalid_id') !== false || strpos($code, 'invalid_order') !== false) {
        return true;
    }

    return false;
}

function np_order_hub_token_response_indicates_missing_order($status_code, $body) {
    $status_code = (int) $status_code;
    if ($status_code !== 404 && $status_code !== 410) {
        return false;
    }
    if (!is_string($body) || trim($body) === '') {
        return false;
    }
    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return false;
    }
    if (array_key_exists('exists', $decoded)) {
        return empty($decoded['exists']);
    }
    $status = sanitize_key((string) ($decoded['status'] ?? ''));
    if (in_array($status, array('not_found', 'missing', 'deleted'), true)) {
        return true;
    }
    $error = sanitize_key((string) ($decoded['error'] ?? ''));
    if (in_array($error, array('not_found', 'order_not_found'), true)) {
        return true;
    }
    $code = sanitize_key((string) ($decoded['code'] ?? ''));
    if ($code === 'woocommerce_rest_shop_order_invalid_id') {
        return true;
    }
    return false;
}

function np_order_hub_check_store_order_exists_via_token($store, $order_id, $timeout = 12) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_store_token', 'Missing store token.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'order-exists');
    if ($endpoint === '') {
        return new WP_Error('missing_store_endpoint', 'Missing store endpoint.');
    }

    $url = add_query_arg(array(
        'order_id' => $order_id,
        'token' => $token,
    ), $endpoint);

    $response = wp_remote_get($url, array(
        'timeout' => (int) $timeout,
        'headers' => array(
            'Accept' => 'application/json',
        ),
    ));
    if (is_wp_error($response)) {
        return $response;
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body = (string) wp_remote_retrieve_body($response);
    if ($status_code === 404 || $status_code === 410) {
        if (np_order_hub_token_response_indicates_missing_order($status_code, $body)) {
            return false;
        }
        return new WP_Error('store_token_ambiguous_not_found', 'Store token request returned ambiguous not-found response.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }
    if ($status_code === 401 || $status_code === 403) {
        return new WP_Error('store_token_unauthorized', 'Store token request unauthorized.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }
    if ($status_code < 200 || $status_code >= 300) {
        return new WP_Error('store_order_exists_failed', 'Store order-exists request failed.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }

    if ($body !== '') {
        $decoded = json_decode($body, true);
        if (is_array($decoded) && array_key_exists('exists', $decoded)) {
            return !empty($decoded['exists']);
        }
    }

    return true;
}

function np_order_hub_sync_deleted_orders($limit = 250, $store_filter = '') {
    global $wpdb;

    $limit = absint($limit);
    if ($limit < 1) {
        $limit = 1;
    } elseif ($limit > 20000) {
        $limit = 20000;
    }
    $store_filter = sanitize_key((string) $store_filter);

    $table = np_order_hub_table_name();
    $stores = np_order_hub_get_stores();

    if ($store_filter !== '') {
        $records = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, store_key, order_id FROM $table WHERE store_key = %s ORDER BY updated_at_gmt DESC, id DESC LIMIT %d",
                $store_filter,
                $limit
            ),
            ARRAY_A
        );
    } else {
        $records = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, store_key, order_id FROM $table ORDER BY updated_at_gmt DESC, id DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );
    }

    $stats = array(
        'checked' => 0,
        'removed' => 0,
        'missing_store' => 0,
        'missing_api' => 0,
        'auth_errors' => 0,
        'token_fallback_checked' => 0,
        'token_missing' => 0,
        'token_auth_errors' => 0,
        'other_errors' => 0,
        'limit' => $limit,
        'store_filter' => $store_filter,
    );

    if (empty($records)) {
        return $stats;
    }

    foreach ($records as $record) {
        if (!is_array($record)) {
            continue;
        }

        $record_id = isset($record['id']) ? absint($record['id']) : 0;
        $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
        $order_id = isset($record['order_id']) ? absint($record['order_id']) : 0;
        if ($record_id < 1 || $store_key === '' || $order_id < 1) {
            continue;
        }

        $stats['checked']++;

        if (empty($stores[$store_key]) || !is_array($stores[$store_key])) {
            $stats['missing_store']++;
            continue;
        }
        $store = $stores[$store_key];

        $fallback_to_token_check = false;

        if (empty($store['consumer_key']) || empty($store['consumer_secret'])) {
            $fallback_to_token_check = true;
            $stats['missing_api']++;
        } else {
            $response = np_order_hub_wc_api_request($store, 'orders/' . $order_id, array(), 12);
            if (is_wp_error($response)) {
                $error_code = (string) $response->get_error_code();
                if ($error_code === 'missing_api_credentials') {
                    $stats['missing_api']++;
                } else {
                    $stats['other_errors']++;
                }
                $fallback_to_token_check = true;
            } else {
                $status_code = (int) wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);

                if (np_order_hub_wc_response_indicates_missing_order($status_code, $body)) {
                    $deleted = $wpdb->delete(
                        $table,
                        array('id' => $record_id),
                        array('%d')
                    );
                    if ($deleted !== false) {
                        $stats['removed']++;
                        $job_key = np_order_hub_print_queue_job_key($store_key, $order_id);
                        if ($job_key !== '') {
                            np_order_hub_print_queue_remove_job($job_key);
                        }
                    } else {
                        $stats['other_errors']++;
                    }
                    continue;
                }

                if ($status_code === 401 || $status_code === 403) {
                    $stats['auth_errors']++;
                    $fallback_to_token_check = true;
                } elseif ($status_code < 200 || $status_code >= 300) {
                    $stats['other_errors']++;
                    $fallback_to_token_check = true;
                }
            }
        }

        if (!$fallback_to_token_check) {
            continue;
        }

        $exists = np_order_hub_check_store_order_exists_via_token($store, $order_id, 12);
        if (is_wp_error($exists)) {
            $error_code = (string) $exists->get_error_code();
            if ($error_code === 'missing_store_token') {
                $stats['token_missing']++;
            } elseif ($error_code === 'store_token_unauthorized') {
                $stats['token_auth_errors']++;
            } else {
                $stats['other_errors']++;
            }
            continue;
        }

        $stats['token_fallback_checked']++;
        if ($exists === false) {
            $deleted = $wpdb->delete(
                $table,
                array('id' => $record_id),
                array('%d')
            );
            if ($deleted !== false) {
                $stats['removed']++;
                $job_key = np_order_hub_print_queue_job_key($store_key, $order_id);
                if ($job_key !== '') {
                    np_order_hub_print_queue_remove_job($job_key);
                }
            } else {
                $stats['other_errors']++;
            }
        }
    }

    return $stats;
}

function np_order_hub_status_sync_normalize_status($status) {
    $status = sanitize_key((string) $status);
    if (strpos($status, 'wc-') === 0) {
        $status = substr($status, 3);
    }
    return $status;
}

function np_order_hub_fetch_store_order_state_via_token($store, $order_id, $timeout = 12) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return new WP_Error('missing_store_token', 'Missing store token.');
    }

    $endpoint = np_order_hub_build_store_api_url($store, 'order-state');
    if ($endpoint === '') {
        return new WP_Error('missing_store_endpoint', 'Missing store endpoint.');
    }

    $url = add_query_arg(array(
        'order_id' => $order_id,
        'token' => $token,
    ), $endpoint);

    $response = wp_remote_get($url, array(
        'timeout' => (int) $timeout,
        'headers' => array(
            'Accept' => 'application/json',
        ),
    ));
    if (is_wp_error($response)) {
        return new WP_Error('token_request_failed', $response->get_error_message());
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body = (string) wp_remote_retrieve_body($response);
    if ($status_code === 404 || $status_code === 410) {
        if (np_order_hub_token_response_indicates_missing_order($status_code, $body)) {
            return array(
                'exists' => false,
                'source' => 'token',
            );
        }
        return new WP_Error('token_ambiguous_not_found', 'Token endpoint returned ambiguous not-found response.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }
    if ($status_code === 401 || $status_code === 403) {
        return new WP_Error('token_unauthorized', 'Token request unauthorized.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }
    if ($status_code < 200 || $status_code >= 300) {
        return new WP_Error('token_bad_response', 'Token request failed.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return new WP_Error('token_bad_payload', 'Invalid token endpoint payload.');
    }

    $exists = !array_key_exists('exists', $decoded) || !empty($decoded['exists']);
    if (!$exists) {
        return array(
            'exists' => false,
            'source' => 'token',
        );
    }

    return array(
        'exists' => true,
        'source' => 'token',
        'status' => np_order_hub_status_sync_normalize_status($decoded['order_status'] ?? $decoded['status'] ?? ''),
        'order_number' => isset($decoded['order_number']) ? sanitize_text_field((string) $decoded['order_number']) : (string) $order_id,
        'currency' => isset($decoded['currency']) ? sanitize_text_field((string) $decoded['currency']) : '',
        'total' => np_order_hub_parse_numeric_value($decoded['total'] ?? 0),
        'date_created' => isset($decoded['date_created']) ? (string) $decoded['date_created'] : '',
        'date_created_gmt' => isset($decoded['date_created_gmt']) ? (string) $decoded['date_created_gmt'] : '',
        'date_modified' => isset($decoded['date_modified']) ? (string) $decoded['date_modified'] : '',
        'date_modified_gmt' => isset($decoded['date_modified_gmt']) ? (string) $decoded['date_modified_gmt'] : '',
    );
}

function np_order_hub_fetch_store_order_state_via_wc($store, $order_id, $timeout = 12) {
    $order_id = absint($order_id);
    if ($order_id < 1) {
        return new WP_Error('missing_order_id', 'Missing order ID.');
    }

    if (empty($store['consumer_key']) || empty($store['consumer_secret'])) {
        return new WP_Error('missing_api_credentials', 'Missing WooCommerce API credentials.');
    }

    $response = np_order_hub_wc_api_request($store, 'orders/' . $order_id, array(), $timeout);
    if (is_wp_error($response)) {
        return new WP_Error('api_request_failed', $response->get_error_message());
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body = (string) wp_remote_retrieve_body($response);
    if (np_order_hub_wc_response_indicates_missing_order($status_code, $body)) {
        return array(
            'exists' => false,
            'source' => 'wc',
        );
    }
    if ($status_code === 401 || $status_code === 403) {
        return new WP_Error('api_unauthorized', 'WooCommerce API unauthorized.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }
    if ($status_code < 200 || $status_code >= 300) {
        return new WP_Error('api_bad_response', 'WooCommerce API bad response.', array(
            'status' => $status_code,
            'body' => $body,
        ));
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return new WP_Error('api_bad_payload', 'Invalid WooCommerce API payload.');
    }

    return array(
        'exists' => true,
        'source' => 'wc',
        'status' => np_order_hub_status_sync_normalize_status($decoded['status'] ?? ''),
        'order_number' => isset($decoded['number']) ? sanitize_text_field((string) $decoded['number']) : (string) $order_id,
        'currency' => isset($decoded['currency']) ? sanitize_text_field((string) $decoded['currency']) : '',
        'total' => np_order_hub_parse_numeric_value($decoded['total'] ?? 0),
        'date_created' => isset($decoded['date_created']) ? (string) $decoded['date_created'] : '',
        'date_created_gmt' => isset($decoded['date_created_gmt']) ? (string) $decoded['date_created_gmt'] : '',
        'date_modified' => isset($decoded['date_modified']) ? (string) $decoded['date_modified'] : '',
        'date_modified_gmt' => isset($decoded['date_modified_gmt']) ? (string) $decoded['date_modified_gmt'] : '',
    );
}

function np_order_hub_fetch_remote_order_state($store, $order_id, $timeout = 12) {
    $token_result = np_order_hub_fetch_store_order_state_via_token($store, $order_id, $timeout);
    if (!is_wp_error($token_result)) {
        if (empty($token_result['exists'])) {
            // Avoid destructive delete on token-only "missing" unless Woo API confirms.
            $wc_verify = np_order_hub_fetch_store_order_state_via_wc($store, $order_id, $timeout);
            if (!is_wp_error($wc_verify)) {
                return $wc_verify;
            }
            return new WP_Error(
                'state_missing_unverified',
                'Token endpoint reported missing order, but Woo API verification failed: ' . $wc_verify->get_error_message(),
                array(
                    'token_source' => 'token',
                    'wc_error_code' => (string) $wc_verify->get_error_code(),
                )
            );
        }
        return $token_result;
    }

    $wc_result = np_order_hub_fetch_store_order_state_via_wc($store, $order_id, $timeout);
    if (!is_wp_error($wc_result)) {
        return $wc_result;
    }

    $token_code = (string) $token_result->get_error_code();
    $wc_code = (string) $wc_result->get_error_code();
    $message = 'Token: ' . $token_result->get_error_message() . '; Woo API: ' . $wc_result->get_error_message();
    return new WP_Error('state_fetch_failed', $message, array(
        'token_error_code' => $token_code,
        'wc_error_code' => $wc_code,
    ));
}

function np_order_hub_fetch_processing_orders_page($store, $per_page, $page) {
    $per_page = absint($per_page);
    if ($per_page < 1) {
        $per_page = 100;
    } elseif ($per_page > 200) {
        $per_page = 200;
    }
    $page = absint($page);
    if ($page < 1) {
        $page = 1;
    }

    $params = array(
        'status' => 'processing',
        'orderby' => 'date',
        'order' => 'desc',
        'per_page' => $per_page,
        'page' => $page,
    );

    $wc_error = null;
    if (!empty($store['consumer_key']) && !empty($store['consumer_secret'])) {
        $response = np_order_hub_wc_api_request($store, 'orders', $params, 25);
        if (!is_wp_error($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
            $body = (string) wp_remote_retrieve_body($response);
            if ($code >= 200 && $code < 300) {
                $orders = $body !== '' ? json_decode($body, true) : null;
                if (is_array($orders)) {
                    $total_pages = (int) wp_remote_retrieve_header($response, 'x-wp-totalpages');
                    if ($total_pages < 1) {
                        $total_pages = 0;
                    }
                    return array(
                        'orders' => $orders,
                        'source' => 'wc',
                        'total_pages' => $total_pages,
                    );
                }
                $wc_error = new WP_Error('wc_bad_payload', 'Invalid WooCommerce order list payload.');
            } else {
                $wc_error = np_order_hub_wc_api_error_response($code, $body);
            }
        } else {
            $wc_error = $response;
        }
    } else {
        $wc_error = new WP_Error('missing_api_credentials', 'Missing WooCommerce API credentials.');
    }

    $token = np_order_hub_get_store_token($store);
    if ($token === '') {
        return $wc_error;
    }
    $endpoint = np_order_hub_build_store_api_url($store, 'orders-export');
    if ($endpoint === '') {
        return $wc_error;
    }

    $url = add_query_arg(array(
        'token' => $token,
        'status' => 'processing',
        'per_page' => $per_page,
        'page' => $page,
    ), $endpoint);
    $token_response = wp_remote_get($url, array(
        'timeout' => 25,
        'headers' => array(
            'Accept' => 'application/json',
        ),
    ));
    if (is_wp_error($token_response)) {
        if (is_wp_error($wc_error)) {
            return new WP_Error(
                'orders_page_fetch_failed',
                'Woo API: ' . $wc_error->get_error_message() . '; Token export: ' . $token_response->get_error_message()
            );
        }
        return $token_response;
    }

    $token_code = (int) wp_remote_retrieve_response_code($token_response);
    $token_body = (string) wp_remote_retrieve_body($token_response);
    if ($token_code < 200 || $token_code >= 300) {
        if (is_wp_error($wc_error)) {
            return new WP_Error(
                'orders_page_fetch_failed',
                'Woo API: ' . $wc_error->get_error_message() . '; Token export HTTP ' . $token_code
            );
        }
        return new WP_Error('orders_export_http_error', 'Token export failed (HTTP ' . $token_code . ').');
    }

    $decoded = $token_body !== '' ? json_decode($token_body, true) : null;
    if (!is_array($decoded)) {
        if (is_wp_error($wc_error)) {
            return new WP_Error(
                'orders_page_fetch_failed',
                'Woo API: ' . $wc_error->get_error_message() . '; Token export returned invalid JSON.'
            );
        }
        return new WP_Error('orders_export_bad_payload', 'Token export payload was invalid.');
    }

    $orders = isset($decoded['orders']) && is_array($decoded['orders']) ? $decoded['orders'] : array();
    $total_pages = isset($decoded['total_pages']) ? absint($decoded['total_pages']) : 0;

    return array(
        'orders' => $orders,
        'source' => 'token',
        'total_pages' => $total_pages,
    );
}

function np_order_hub_backfill_processing_orders($store_filter = '', $max_per_store = 200) {
    global $wpdb;

    $table = np_order_hub_table_name();
    $stores = np_order_hub_get_stores();
    $store_filter = sanitize_key((string) $store_filter);
    $max_per_store = absint($max_per_store);
    if ($max_per_store < 1) {
        $max_per_store = 200;
    } elseif ($max_per_store > 2000) {
        $max_per_store = 2000;
    }

    if ($store_filter !== '') {
        if (empty($stores[$store_filter]) || !is_array($stores[$store_filter])) {
            return new WP_Error('unknown_store', 'Unknown store key.');
        }
        $stores = array($store_filter => $stores[$store_filter]);
    }

    $stats = array(
        'stores' => 0,
        'checked' => 0,
        'inserted' => 0,
        'updated' => 0,
        'errors' => 0,
        'source_wc' => 0,
        'source_token' => 0,
    );

    foreach ($stores as $store_key => $store) {
        if (!is_array($store)) {
            continue;
        }
        $stats['stores']++;

        $per_page = $max_per_store > 100 ? 100 : $max_per_store;
        $max_pages = (int) ceil($max_per_store / $per_page);
        if ($max_pages < 1) {
            $max_pages = 1;
        }
        $processed_for_store = 0;

        for ($page = 1; $page <= $max_pages; $page++) {
            $page_result = np_order_hub_fetch_processing_orders_page($store, $per_page, $page);
            if (is_wp_error($page_result)) {
                $stats['errors']++;
                break;
            }

            $orders = isset($page_result['orders']) && is_array($page_result['orders']) ? $page_result['orders'] : array();
            $source = isset($page_result['source']) ? (string) $page_result['source'] : '';
            if ($source === 'wc') {
                $stats['source_wc']++;
            } elseif ($source === 'token') {
                $stats['source_token']++;
            }
            if (empty($orders)) {
                break;
            }

            foreach ($orders as $data) {
                if (!is_array($data)) {
                    continue;
                }
                $order_id = absint($data['id'] ?? 0);
                if ($order_id < 1) {
                    continue;
                }
                $status = sanitize_key((string) ($data['status'] ?? ''));
                if ($status !== 'processing') {
                    continue;
                }

                if ($processed_for_store >= $max_per_store) {
                    break 2;
                }
                $processed_for_store++;
                $stats['checked']++;

                $order_number = isset($data['number']) ? sanitize_text_field((string) $data['number']) : (string) $order_id;
                $currency = isset($data['currency']) ? sanitize_text_field((string) $data['currency']) : '';
                $total = np_order_hub_parse_numeric_value($data['total'] ?? 0);
                if ($total === null) {
                    $total = 0.0;
                }

                $date_created_gmt = np_order_hub_parse_datetime_gmt(
                    $data['date_created_gmt'] ?? '',
                    $data['date_created'] ?? ''
                );
                $date_modified_gmt = np_order_hub_parse_datetime_gmt(
                    $data['date_modified_gmt'] ?? '',
                    $data['date_modified'] ?? ''
                );

                $existing = $wpdb->get_row(
                    $wpdb->prepare(
                        "SELECT id, payload FROM $table WHERE store_key = %s AND order_id = %d",
                        $store_key,
                        $order_id
                    ),
                    ARRAY_A
                );
                $existing_id = $existing ? (int) $existing['id'] : 0;
                $existing_bucket = $existing ? np_order_hub_extract_delivery_bucket_from_payload_data($existing['payload']) : '';
                $existing_payload = array();
                if ($existing && !empty($existing['payload'])) {
                    $decoded_existing_payload = json_decode((string) $existing['payload'], true);
                    if (is_array($decoded_existing_payload)) {
                        $existing_payload = $decoded_existing_payload;
                    }
                }

                $store_bucket = np_order_hub_get_active_store_delivery_bucket($store);
                $bucket_to_set = $existing_bucket !== '' ? $existing_bucket : $store_bucket;
                $data[NP_ORDER_HUB_DELIVERY_BUCKET_KEY] = $bucket_to_set;
                if (!empty($existing_payload['np_reklamasjon']) && empty($data['np_reklamasjon'])) {
                    $data['np_reklamasjon'] = true;
                }
                if (!empty($existing_payload['np_reklamasjon_source_order']) && empty($data['np_reklamasjon_source_order'])) {
                    $data['np_reklamasjon_source_order'] = (int) $existing_payload['np_reklamasjon_source_order'];
                }
                if (!empty($existing_payload['np_bytte_storrelse']) && empty($data['np_bytte_storrelse'])) {
                    $data['np_bytte_storrelse'] = true;
                }
                if (!empty($existing_payload['np_bytte_storrelse_source_order']) && empty($data['np_bytte_storrelse_source_order'])) {
                    $data['np_bytte_storrelse_source_order'] = (int) $existing_payload['np_bytte_storrelse_source_order'];
                }

                $record = array(
                    'store_key' => $store_key,
                    'store_name' => isset($store['name']) ? (string) $store['name'] : '',
                    'store_url' => isset($store['url']) ? (string) $store['url'] : '',
                    'order_id' => $order_id,
                    'order_number' => $order_number,
                    'status' => $status,
                    'currency' => $currency,
                    'total' => (float) $total,
                    'date_created_gmt' => $date_created_gmt !== '' ? $date_created_gmt : null,
                    'date_modified_gmt' => $date_modified_gmt !== '' ? $date_modified_gmt : null,
                    'order_admin_url' => np_order_hub_build_admin_order_url($store, $order_id),
                    'payload' => wp_json_encode($data),
                );

                $now_gmt = current_time('mysql', true);
                if ($existing_id > 0) {
                    $record['updated_at_gmt'] = $now_gmt;
                    $updated = $wpdb->update($table, $record, array('id' => $existing_id));
                    if ($updated === false) {
                        $stats['errors']++;
                    } else {
                        $stats['updated']++;
                    }
                } else {
                    $record['created_at_gmt'] = $date_created_gmt !== '' ? $date_created_gmt : $now_gmt;
                    $record['updated_at_gmt'] = $now_gmt;
                    $inserted = $wpdb->insert($table, $record);
                    if ($inserted === false) {
                        $stats['errors']++;
                    } else {
                        $stats['inserted']++;
                    }
                }
            }

            $total_pages = isset($page_result['total_pages']) ? absint($page_result['total_pages']) : 0;
            if (count($orders) < $per_page || ($total_pages > 0 && $page >= $total_pages) || $processed_for_store >= $max_per_store) {
                break;
            }
        }
    }

    return $stats;
}

function np_order_hub_status_sync_get_cursor() {
    return absint(get_option(NP_ORDER_HUB_STATUS_SYNC_CURSOR_OPTION, 0));
}

function np_order_hub_status_sync_set_cursor($cursor) {
    update_option(NP_ORDER_HUB_STATUS_SYNC_CURSOR_OPTION, absint($cursor), false);
}

function np_order_hub_sync_order_statuses($limit = 250) {
    global $wpdb;

    $limit = absint($limit);
    if ($limit < 1) {
        $limit = 1;
    } elseif ($limit > 5000) {
        $limit = 5000;
    }

    $table = np_order_hub_table_name();
    $stores = np_order_hub_get_stores();
    $cursor = np_order_hub_status_sync_get_cursor();
    $wrapped = false;

    $records = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT id, store_key, order_id, order_number, status, currency, total, date_created_gmt, date_modified_gmt, payload
             FROM $table
             WHERE id > %d
             ORDER BY id ASC
             LIMIT %d",
            $cursor,
            $limit
        ),
        ARRAY_A
    );

    if (empty($records) && $cursor > 0) {
        $wrapped = true;
        $cursor = 0;
        $records = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, store_key, order_id, order_number, status, currency, total, date_created_gmt, date_modified_gmt, payload
                 FROM $table
                 WHERE id > %d
                 ORDER BY id ASC
                 LIMIT %d",
                $cursor,
                $limit
            ),
            ARRAY_A
        );
    }

    $stats = array(
        'checked' => 0,
        'updated' => 0,
        'removed' => 0,
        'missing_store' => 0,
        'token_checks' => 0,
        'wc_checks' => 0,
        'fetch_errors' => 0,
        'other_errors' => 0,
        'start_cursor' => np_order_hub_status_sync_get_cursor(),
        'end_cursor' => $cursor,
        'wrapped' => $wrapped ? 1 : 0,
    );

    if (empty($records)) {
        np_order_hub_status_sync_set_cursor(0);
        $stats['end_cursor'] = 0;
        return $stats;
    }

    foreach ($records as $record) {
        if (!is_array($record)) {
            continue;
        }

        $record_id = isset($record['id']) ? absint($record['id']) : 0;
        $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
        $order_id = isset($record['order_id']) ? absint($record['order_id']) : 0;
        if ($record_id < 1 || $store_key === '' || $order_id < 1) {
            continue;
        }

        $stats['checked']++;
        $stats['end_cursor'] = $record_id;

        if (empty($stores[$store_key]) || !is_array($stores[$store_key])) {
            $stats['missing_store']++;
            continue;
        }
        $store = $stores[$store_key];

        $state = np_order_hub_fetch_remote_order_state($store, $order_id, 12);
        if (is_wp_error($state)) {
            $stats['fetch_errors']++;
            continue;
        }

        $source = isset($state['source']) ? (string) $state['source'] : '';
        if ($source === 'token') {
            $stats['token_checks']++;
        } elseif ($source === 'wc') {
            $stats['wc_checks']++;
        }

        if (empty($state['exists'])) {
            $deleted = $wpdb->delete(
                $table,
                array('id' => $record_id),
                array('%d')
            );
            if ($deleted !== false) {
                $stats['removed']++;
                $job_key = np_order_hub_print_queue_job_key($store_key, $order_id);
                if ($job_key !== '') {
                    np_order_hub_print_queue_remove_job($job_key);
                }
            } else {
                $stats['other_errors']++;
            }
            continue;
        }

        $remote_status = np_order_hub_status_sync_normalize_status($state['status'] ?? '');
        $remote_order_number = isset($state['order_number']) ? sanitize_text_field((string) $state['order_number']) : '';
        $remote_currency = isset($state['currency']) ? sanitize_text_field((string) $state['currency']) : '';
        $remote_total = np_order_hub_parse_numeric_value($state['total'] ?? 0);
        if ($remote_total === null) {
            $remote_total = 0.0;
        }
        $remote_created_gmt = np_order_hub_parse_datetime_gmt(
            $state['date_created_gmt'] ?? '',
            $state['date_created'] ?? ''
        );
        $remote_modified_gmt = np_order_hub_parse_datetime_gmt(
            $state['date_modified_gmt'] ?? '',
            $state['date_modified'] ?? ''
        );

        $update = array();
        if ($remote_status !== '' && $remote_status !== sanitize_key((string) ($record['status'] ?? ''))) {
            $update['status'] = $remote_status;
        }
        if ($remote_order_number !== '' && $remote_order_number !== (string) ($record['order_number'] ?? '')) {
            $update['order_number'] = $remote_order_number;
        }
        if ($remote_currency !== '' && $remote_currency !== (string) ($record['currency'] ?? '')) {
            $update['currency'] = $remote_currency;
        }
        $record_total = np_order_hub_parse_numeric_value($record['total'] ?? 0);
        if ($record_total === null) {
            $record_total = 0.0;
        }
        if (abs((float) $remote_total - (float) $record_total) > 0.0001) {
            $update['total'] = (float) $remote_total;
        }
        if ($remote_created_gmt !== '' && $remote_created_gmt !== (string) ($record['date_created_gmt'] ?? '')) {
            $update['date_created_gmt'] = $remote_created_gmt;
        }
        if ($remote_modified_gmt !== '' && $remote_modified_gmt !== (string) ($record['date_modified_gmt'] ?? '')) {
            $update['date_modified_gmt'] = $remote_modified_gmt;
        }

        $payload_changed = false;
        $payload = array();
        if (!empty($record['payload'])) {
            $decoded_payload = json_decode((string) $record['payload'], true);
            if (is_array($decoded_payload)) {
                $payload = $decoded_payload;
            }
        }
        if (!empty($payload)) {
            if ($remote_status !== '' && (!isset($payload['status']) || np_order_hub_status_sync_normalize_status($payload['status']) !== $remote_status)) {
                $payload['status'] = $remote_status;
                $payload_changed = true;
            }
            if ($remote_order_number !== '' && (!isset($payload['number']) || (string) $payload['number'] !== $remote_order_number)) {
                $payload['number'] = $remote_order_number;
                $payload_changed = true;
            }
            if ($remote_currency !== '' && (!isset($payload['currency']) || (string) $payload['currency'] !== $remote_currency)) {
                $payload['currency'] = $remote_currency;
                $payload_changed = true;
            }
            $payload_total = np_order_hub_parse_numeric_value($payload['total'] ?? null);
            if ($payload_total === null || abs((float) $payload_total - (float) $remote_total) > 0.0001) {
                $payload['total'] = wc_format_decimal((float) $remote_total, 4);
                $payload_changed = true;
            }
            if (!empty($state['date_created']) && (!isset($payload['date_created']) || (string) $payload['date_created'] !== (string) $state['date_created'])) {
                $payload['date_created'] = (string) $state['date_created'];
                $payload_changed = true;
            }
            if (!empty($state['date_created_gmt']) && (!isset($payload['date_created_gmt']) || (string) $payload['date_created_gmt'] !== (string) $state['date_created_gmt'])) {
                $payload['date_created_gmt'] = (string) $state['date_created_gmt'];
                $payload_changed = true;
            }
            if (!empty($state['date_modified']) && (!isset($payload['date_modified']) || (string) $payload['date_modified'] !== (string) $state['date_modified'])) {
                $payload['date_modified'] = (string) $state['date_modified'];
                $payload_changed = true;
            }
            if (!empty($state['date_modified_gmt']) && (!isset($payload['date_modified_gmt']) || (string) $payload['date_modified_gmt'] !== (string) $state['date_modified_gmt'])) {
                $payload['date_modified_gmt'] = (string) $state['date_modified_gmt'];
                $payload_changed = true;
            }
        }
        if ($payload_changed) {
            $update['payload'] = wp_json_encode($payload);
        }

        if (empty($update)) {
            continue;
        }

        $update['updated_at_gmt'] = current_time('mysql', true);
        $updated = $wpdb->update($table, $update, array('id' => $record_id));
        if ($updated === false) {
            $stats['other_errors']++;
        } else {
            $stats['updated']++;
        }
    }

    np_order_hub_status_sync_set_cursor((int) ($stats['end_cursor'] ?? 0));

    return $stats;
}

function np_order_hub_debug_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $queue_notice = null;
    $agent_token = np_order_hub_get_print_agent_token(true);
    if (!empty($_POST['np_order_hub_print_queue_action'])) {
        check_admin_referer('np_order_hub_debug_print_queue');
        $action = sanitize_key((string) $_POST['np_order_hub_print_queue_action']);
        if ($action === 'run_due') {
            $ran = np_order_hub_print_queue_run_due_jobs(20);
            $queue_notice = array(
                'type' => 'updated',
                'message' => 'Ran ' . (int) $ran . ' due print job(s).',
            );
        } elseif ($action === 'sync_deleted') {
            $limit = isset($_POST['np_order_hub_deleted_sync_limit']) ? absint($_POST['np_order_hub_deleted_sync_limit']) : 5000;
            $store_filter = isset($_POST['np_order_hub_deleted_sync_store']) ? sanitize_key((string) wp_unslash($_POST['np_order_hub_deleted_sync_store'])) : '';
            $result = np_order_hub_sync_deleted_orders($limit, $store_filter);
            if (is_wp_error($result)) {
                $queue_notice = array(
                    'type' => 'error',
                    'message' => $result->get_error_message(),
                );
            } else {
                $scope = isset($result['store_filter']) && $result['store_filter'] !== '' ? (string) $result['store_filter'] : 'all stores';
                $queue_notice = array(
                    'type' => 'updated',
                    'message' => sprintf(
                        'Deleted-order sync done (%s). Checked: %d, removed from hub: %d, Woo missing creds: %d, Woo auth errors: %d, token checks: %d, token missing: %d, token auth errors: %d, other errors: %d.',
                        $scope,
                        (int) ($result['checked'] ?? 0),
                        (int) ($result['removed'] ?? 0),
                        (int) ($result['missing_api'] ?? 0),
                        (int) ($result['auth_errors'] ?? 0),
                        (int) ($result['token_fallback_checked'] ?? 0),
                        (int) ($result['token_missing'] ?? 0),
                        (int) ($result['token_auth_errors'] ?? 0),
                        (int) ($result['other_errors'] ?? 0)
                    ),
                );
            }
        } elseif ($action === 'sync_statuses') {
            $limit = isset($_POST['np_order_hub_status_sync_limit']) ? absint($_POST['np_order_hub_status_sync_limit']) : NP_ORDER_HUB_STATUS_SYNC_LIMIT;
            $result = np_order_hub_sync_order_statuses($limit);
            if (is_wp_error($result)) {
                $queue_notice = array(
                    'type' => 'error',
                    'message' => $result->get_error_message(),
                );
            } else {
                $queue_notice = array(
                    'type' => 'updated',
                    'message' => sprintf(
                        'Status-sync done. Checked: %d, updated: %d, removed: %d, token checks: %d, Woo checks: %d, fetch errors: %d, other errors: %d.',
                        (int) ($result['checked'] ?? 0),
                        (int) ($result['updated'] ?? 0),
                        (int) ($result['removed'] ?? 0),
                        (int) ($result['token_checks'] ?? 0),
                        (int) ($result['wc_checks'] ?? 0),
                        (int) ($result['fetch_errors'] ?? 0),
                        (int) ($result['other_errors'] ?? 0)
                    ),
                );
            }
        } elseif ($action === 'rebuild_processing') {
            $store_filter = isset($_POST['np_order_hub_rebuild_store']) ? sanitize_key((string) wp_unslash($_POST['np_order_hub_rebuild_store'])) : '';
            $max_per_store = isset($_POST['np_order_hub_rebuild_limit']) ? absint($_POST['np_order_hub_rebuild_limit']) : 300;
            $result = np_order_hub_backfill_processing_orders($store_filter, $max_per_store);
            if (is_wp_error($result)) {
                $queue_notice = array(
                    'type' => 'error',
                    'message' => $result->get_error_message(),
                );
            } else {
                $scope = $store_filter !== '' ? $store_filter : 'all stores';
                $queue_notice = array(
                    'type' => 'updated',
                    'message' => sprintf(
                        'Processing rebuild done (%s). Stores: %d, checked: %d, inserted: %d, updated: %d, page fetches via Woo: %d, via token: %d, errors: %d.',
                        $scope,
                        (int) ($result['stores'] ?? 0),
                        (int) ($result['checked'] ?? 0),
                        (int) ($result['inserted'] ?? 0),
                        (int) ($result['updated'] ?? 0),
                        (int) ($result['source_wc'] ?? 0),
                        (int) ($result['source_token'] ?? 0),
                        (int) ($result['errors'] ?? 0)
                    ),
                );
            }
        } elseif ($action === 'retry_job') {
            $job_key = sanitize_text_field((string) ($_POST['np_order_hub_print_job_key'] ?? ''));
            $retry = np_order_hub_print_queue_retry_now($job_key);
            if (is_wp_error($retry)) {
                $queue_notice = array(
                    'type' => 'error',
                    'message' => $retry->get_error_message(),
                );
            } else {
                $queue_notice = array(
                    'type' => 'updated',
                    'message' => 'Print job queued for retry.',
                );
            }
        }
    }
    if (!empty($_POST['np_order_hub_print_agent_token_action'])) {
        check_admin_referer('np_order_hub_debug_print_queue');
        $action = sanitize_key((string) $_POST['np_order_hub_print_agent_token_action']);
        if ($action === 'regenerate') {
            $agent_token = np_order_hub_regenerate_print_agent_token();
            $queue_notice = array(
                'type' => 'updated',
                'message' => 'Print agent token regenerated.',
            );
        }
    }

    global $wpdb;
    $table = np_order_hub_table_name();
    $records = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at_gmt DESC LIMIT 5", ARRAY_A);
    $jobs = np_order_hub_print_queue_get_jobs();
    uasort($jobs, function ($a, $b) {
        $a_time = isset($a['updated_at_gmt']) ? strtotime((string) $a['updated_at_gmt']) : 0;
        $b_time = isset($b['updated_at_gmt']) ? strtotime((string) $b['updated_at_gmt']) : 0;
        if ($a_time === $b_time) {
            return 0;
        }
        return $a_time > $b_time ? -1 : 1;
    });

    echo '<div class="wrap">';
    echo '<h1>Order Hub Debug</h1>';
    echo '<p>Shows print queue status and latest webhook payloads stored by the hub.</p>';

    if (is_array($queue_notice) && !empty($queue_notice['message'])) {
        $notice_class = $queue_notice['type'] === 'error' ? 'notice notice-error' : 'notice notice-success';
        echo '<div class="' . esc_attr($notice_class) . '"><p>' . esc_html((string) $queue_notice['message']) . '</p></div>';
    }

    echo '<h2 style="margin-top:18px;">Auto print queue (phase 1)</h2>';
    echo '<p>Queued for root stores only, status <code>processing</code>, bucket <code>Levering 3-5 dager</code>. Delay: 4 min. Retry: every 60 sec.</p>';
    $claim_url = rest_url('np-order-hub/v1/print-agent/claim');
    $finish_url = rest_url('np-order-hub/v1/print-agent/finish');
    echo '<p><strong>Print agent claim URL:</strong> <code>' . esc_html($claim_url) . '</code><br />';
    echo '<strong>Print agent finish URL:</strong> <code>' . esc_html($finish_url) . '</code><br />';
    echo '<strong>Print agent token:</strong> <code>' . esc_html($agent_token) . '</code></p>';
    echo '<form method="post" style="margin:0 0 10px;">';
    wp_nonce_field('np_order_hub_debug_print_queue');
    echo '<button class="button" type="submit" name="np_order_hub_print_agent_token_action" value="regenerate">Regenerate print token</button>';
    echo '</form>';
    echo '<form method="post" style="margin:10px 0 14px;">';
    wp_nonce_field('np_order_hub_debug_print_queue');
    echo '<button class="button button-primary" type="submit" name="np_order_hub_print_queue_action" value="run_due">Run due jobs now</button>';
    echo '</form>';
    echo '<form method="post" style="margin:0 0 18px;">';
    wp_nonce_field('np_order_hub_debug_print_queue');
    echo '<input type="hidden" name="np_order_hub_print_queue_action" value="sync_deleted" />';
    echo '<label for="np-order-hub-deleted-sync-limit" style="margin-right:8px;">Check latest records:</label>';
    echo '<input id="np-order-hub-deleted-sync-limit" name="np_order_hub_deleted_sync_limit" type="number" min="10" max="20000" value="5000" style="width:90px; margin-right:8px;" />';
    echo '<label for="np-order-hub-deleted-sync-store" style="margin-right:8px;">Store key (optional):</label>';
    echo '<input id="np-order-hub-deleted-sync-store" name="np_order_hub_deleted_sync_store" type="text" value="" placeholder="tangen_root_nordicprofil_no" style="width:220px; margin-right:8px;" />';
    echo '<button class="button" type="submit">Sync already deleted orders</button>';
    echo '<p class="description" style="margin-top:6px;">Checks hub records against WooCommerce API and falls back to token endpoint <code>order-exists</code> when API credentials fail.</p>';
    echo '</form>';
    echo '<form method="post" style="margin:0 0 18px;">';
    wp_nonce_field('np_order_hub_debug_print_queue');
    echo '<input type="hidden" name="np_order_hub_print_queue_action" value="sync_statuses" />';
    echo '<label for="np-order-hub-status-sync-limit" style="margin-right:8px;">Status-sync batch size:</label>';
    echo '<input id="np-order-hub-status-sync-limit" name="np_order_hub_status_sync_limit" type="number" min="10" max="5000" value="' . esc_attr((string) NP_ORDER_HUB_STATUS_SYNC_LIMIT) . '" style="width:90px; margin-right:8px;" />';
    echo '<button class="button" type="submit">Sync statuses now</button>';
    echo '<p class="description" style="margin-top:6px;">Runs one reconciliation batch against subsite order status (auto-runs every 5 minutes in background).</p>';
    echo '</form>';
    echo '<form method="post" style="margin:0 0 18px;">';
    wp_nonce_field('np_order_hub_debug_print_queue');
    echo '<input type="hidden" name="np_order_hub_print_queue_action" value="rebuild_processing" />';
    echo '<label for="np-order-hub-rebuild-store" style="margin-right:8px;">Store key (optional):</label>';
    echo '<input id="np-order-hub-rebuild-store" name="np_order_hub_rebuild_store" type="text" value="" placeholder="tangen_root_nordicprofil_no" style="width:220px; margin-right:8px;" />';
    echo '<label for="np-order-hub-rebuild-limit" style="margin-right:8px;">Max per store:</label>';
    echo '<input id="np-order-hub-rebuild-limit" name="np_order_hub_rebuild_limit" type="number" min="50" max="2000" value="300" style="width:90px; margin-right:8px;" />';
    echo '<button class="button" type="submit">Rebuild processing orders now</button>';
    echo '<p class="description" style="margin-top:6px;">Fetches <code>processing</code> orders and upserts them back into hub (tries Woo API first, falls back to token export, no email/webhook side effects).</p>';
    echo '</form>';

    if (empty($jobs)) {
        echo '<div class="notice notice-info inline"><p>No print jobs queued yet.</p></div>';
    } else {
        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th>Order</th>';
        echo '<th>Store</th>';
        echo '<th>Status</th>';
        echo '<th>Attempts</th>';
        echo '<th>Scheduled</th>';
        echo '<th>Updated</th>';
        echo '<th>Document</th>';
        echo '<th>Last error</th>';
        echo '<th>Actions</th>';
        echo '</tr></thead><tbody>';

        $shown = 0;
        foreach ($jobs as $job_key => $job) {
            if (!is_array($job)) {
                continue;
            }
            $shown++;
            if ($shown > 50) {
                break;
            }
            $order_id = isset($job['order_id']) ? (int) $job['order_id'] : 0;
            $order_number = isset($job['order_number']) ? (string) $job['order_number'] : '';
            $record_id = isset($job['record_id']) ? (int) $job['record_id'] : 0;
            $order_label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
            if ($record_id > 0) {
                $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . $record_id);
                $order_label = '<a href="' . esc_url($details_url) . '">' . esc_html($order_label) . '</a>';
            } else {
                $order_label = esc_html($order_label);
            }
            $store_name = isset($job['store_name']) && $job['store_name'] !== '' ? (string) $job['store_name'] : (isset($job['store_key']) ? (string) $job['store_key'] : '');
            $status = isset($job['status']) ? (string) $job['status'] : 'pending';
            $attempts = isset($job['attempts']) ? (int) $job['attempts'] : 0;
            $max_attempts = isset($job['max_attempts']) ? (int) $job['max_attempts'] : NP_ORDER_HUB_PRINT_QUEUE_MAX_ATTEMPTS;
            $scheduled = isset($job['scheduled_for_gmt']) ? (string) $job['scheduled_for_gmt'] : '';
            $updated = isset($job['updated_at_gmt']) ? (string) $job['updated_at_gmt'] : '';
            $document_url = isset($job['document_url']) ? (string) $job['document_url'] : '';
            $document_name = isset($job['document_filename']) ? (string) $job['document_filename'] : 'PDF';
            $last_error = isset($job['last_error']) ? (string) $job['last_error'] : '';
            $logs = isset($job['log']) && is_array($job['log']) ? $job['log'] : array();

            echo '<tr>';
            echo '<td>' . $order_label . '</td>';
            echo '<td>' . esc_html($store_name) . '</td>';
            echo '<td>' . esc_html($status) . '</td>';
            echo '<td>' . esc_html($attempts . '/' . $max_attempts) . '</td>';
            echo '<td>' . esc_html($scheduled !== '' ? get_date_from_gmt($scheduled, 'd.m.y H:i:s') : '—') . '</td>';
            echo '<td>' . esc_html($updated !== '' ? get_date_from_gmt($updated, 'd.m.y H:i:s') : '—') . '</td>';
            if ($document_url !== '') {
                echo '<td><a href="' . esc_url($document_url) . '" target="_blank" rel="noopener">' . esc_html($document_name) . '</a></td>';
            } else {
                echo '<td>—</td>';
            }
            echo '<td>' . esc_html($last_error !== '' ? $last_error : '—') . '</td>';
            echo '<td>';
            echo '<form method="post" style="display:inline;">';
            wp_nonce_field('np_order_hub_debug_print_queue');
            echo '<input type="hidden" name="np_order_hub_print_queue_action" value="retry_job" />';
            echo '<input type="hidden" name="np_order_hub_print_job_key" value="' . esc_attr((string) $job_key) . '" />';
            echo '<button class="button button-small" type="submit">Retry now</button>';
            echo '</form>';
            if (!empty($logs)) {
                echo '<details style="margin-top:6px;"><summary>Log</summary><pre style="white-space:pre-wrap; max-width:480px;">' . esc_html(implode("\n", $logs)) . '</pre></details>';
            }
            echo '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    echo '<h2 style="margin-top:22px;">Latest webhook payloads</h2>';

    if (empty($records)) {
        echo '<div class="notice notice-info"><p>No webhook payloads found yet.</p></div>';
        echo '</div>';
        return;
    }

    foreach ($records as $record) {
        $order_id = isset($record['order_id']) ? (int) $record['order_id'] : 0;
        $order_number = isset($record['order_number']) ? (string) $record['order_number'] : '';
        $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
        $store_key = isset($record['store_key']) ? (string) $record['store_key'] : '';
        $store_name = isset($record['store_name']) ? (string) $record['store_name'] : '';
        $created = '';
        if (!empty($record['created_at_gmt']) && $record['created_at_gmt'] !== '0000-00-00 00:00:00') {
            $created = get_date_from_gmt($record['created_at_gmt'], 'd.m.y');
        }
        $payload = array();
        if (!empty($record['payload'])) {
            $decoded = json_decode($record['payload'], true);
            if (is_array($decoded)) {
                $payload = $decoded;
            }
        }
        $store = np_order_hub_get_store_by_key($store_key);
        $access_key = $payload ? np_order_hub_extract_access_key($payload) : '';
        $packing_url = np_order_hub_build_packing_slip_url($store, $order_id, $order_number, $payload);
        $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $record['id']);

        echo '<div class="card" style="margin:16px 0; padding:16px;">';
        echo '<h2 style="margin:0 0 8px;">Order ' . esc_html($label) . '</h2>';
        if ($store_name !== '') {
            echo '<p><strong>Store:</strong> ' . esc_html($store_name) . '</p>';
        }
        if ($created !== '') {
            echo '<p><strong>Received:</strong> ' . esc_html($created) . '</p>';
        }
        echo '<p><strong>Access key:</strong> ' . esc_html($access_key !== '' ? $access_key : 'missing') . '</p>';
        echo '<p><strong>Packing slip URL:</strong> ' . ($packing_url !== '' ? '<code>' . esc_html($packing_url) . '</code>' : 'missing') . '</p>';
        echo '<p><a class="button" href="' . esc_url($details_url) . '">Open details</a></p>';

        $payload_text = '';
        if (!empty($payload)) {
            $payload_text = wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } elseif (!empty($record['payload'])) {
            $payload_text = (string) $record['payload'];
        }
        if ($payload_text === '') {
            $payload_text = 'Payload missing or could not be decoded.';
        }

        echo '<details style="margin-top:12px;">';
        echo '<summary>Payload</summary>';
        echo '<pre style="max-height:360px; overflow:auto; background:#f6f7f7; padding:12px; border:1px solid #dcdcde;">' . esc_html($payload_text) . '</pre>';
        echo '</details>';
        echo '</div>';
    }

    echo '</div>';
}

function np_order_hub_stores_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $stores = np_order_hub_get_stores();
    $edit_store = null;
    $connector_setup_key = np_order_hub_get_connector_setup_key(true);

    if (!empty($_POST['np_order_hub_connector_setup_action'])) {
        check_admin_referer('np_order_hub_connector_setup_key');
        $action = sanitize_key((string) $_POST['np_order_hub_connector_setup_action']);
        if ($action === 'regenerate') {
            $connector_setup_key = wp_generate_password(48, false, false);
            update_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, $connector_setup_key, false);
            echo '<div class="updated"><p>Connector setup key regenerated.</p></div>';
        } elseif ($action === 'save') {
            $candidate = trim((string) ($_POST['np_order_hub_connector_setup_key'] ?? ''));
            if ($candidate === '') {
                echo '<div class="error"><p>Connector setup key cannot be empty.</p></div>';
            } else {
                $connector_setup_key = $candidate;
                update_option(NP_ORDER_HUB_CONNECTOR_SETUP_KEY_OPTION, $connector_setup_key, false);
                echo '<div class="updated"><p>Connector setup key saved.</p></div>';
            }
        }
    }

    if (!empty($_POST['np_order_hub_update_store'])) {
        check_admin_referer('np_order_hub_update_store');
        $key = sanitize_key((string) ($_POST['store_key'] ?? ''));
        $existing = (isset($stores[$key]) && is_array($stores[$key])) ? $stores[$key] : null;
        $name = sanitize_text_field((string) ($_POST['store_name'] ?? ''));
        $url = esc_url_raw((string) ($_POST['store_url'] ?? ''));
        $secret = trim((string) ($_POST['store_secret'] ?? ''));
        $token = sanitize_text_field((string) ($_POST['store_token'] ?? ''));
        $consumer_key = sanitize_text_field((string) ($_POST['store_consumer_key'] ?? ''));
        $consumer_secret = sanitize_text_field((string) ($_POST['store_consumer_secret'] ?? ''));
        $packing_slip_url = np_order_hub_sanitize_url_template((string) ($_POST['packing_slip_url'] ?? (is_array($existing) && isset($existing['packing_slip_url']) ? $existing['packing_slip_url'] : '')));
        $type = sanitize_key((string) ($_POST['order_url_type'] ?? NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE));
        $type = $type === 'hpos' ? 'hpos' : 'legacy';
        $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? (is_array($existing) && isset($existing['delivery_bucket']) ? $existing['delivery_bucket'] : '')));
        $switch_date_raw = sanitize_text_field((string) ($_POST['delivery_bucket_switch_date'] ?? (is_array($existing) && isset($existing['delivery_bucket_switch_date']) ? $existing['delivery_bucket_switch_date'] : '')));
        $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
        $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($_POST['delivery_bucket_after'] ?? (is_array($existing) && isset($existing['delivery_bucket_after']) ? $existing['delivery_bucket_after'] : '')));
        $shipping_window_enabled = !empty($_POST['shipping_window_enabled']) ? '1' : '0';
        $shipping_window_start_date = sanitize_text_field((string) ($_POST['shipping_window_start_date'] ?? (is_array($existing) && isset($existing['shipping_window_start_date']) ? $existing['shipping_window_start_date'] : '')));
        $shipping_window_end_date = sanitize_text_field((string) ($_POST['shipping_window_end_date'] ?? (is_array($existing) && isset($existing['shipping_window_end_date']) ? $existing['shipping_window_end_date'] : '')));
        $shipping_window_method_keys = (string) ($_POST['shipping_window_method_keys'] ?? np_order_hub_shipping_method_keys_to_text(is_array($existing) && isset($existing['shipping_window_method_keys']) ? $existing['shipping_window_method_keys'] : array()));
        $shipping_window_include_postnord = !empty($_POST['shipping_window_include_postnord_parcel_locker']) ? '1' : '0';

        if (!$existing) {
            echo '<div class="error"><p>Store not found.</p></div>';
        } else {
            $upsert = np_order_hub_store_upsert(array(
                'key' => $key,
                'name' => $name,
                'url' => $url,
                'secret' => $secret,
                'token' => $token,
                'consumer_key' => $consumer_key,
                'consumer_secret' => $consumer_secret,
                'packing_slip_url' => $packing_slip_url,
                'order_url_type' => $type,
                'delivery_bucket' => $delivery_bucket,
                'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
                'delivery_bucket_after' => $delivery_bucket_after,
                'shipping_window_enabled' => $shipping_window_enabled,
                'shipping_window_start_date' => $shipping_window_start_date,
                'shipping_window_end_date' => $shipping_window_end_date,
                'shipping_window_method_keys' => $shipping_window_method_keys,
                'shipping_window_include_postnord_parcel_locker' => $shipping_window_include_postnord,
            ));
            if (is_wp_error($upsert)) {
                $edit_store = array(
                    'key' => $key,
                    'name' => $name,
                    'url' => $url,
                    'secret' => $secret,
                    'token' => $token,
                    'consumer_key' => $consumer_key,
                    'consumer_secret' => $consumer_secret,
                    'packing_slip_url' => $packing_slip_url,
                    'order_url_type' => $type,
                    'delivery_bucket' => $delivery_bucket,
                    'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
                    'delivery_bucket_after' => $delivery_bucket_after,
                    'shipping_window_enabled' => $shipping_window_enabled,
                    'shipping_window_start_date' => $shipping_window_start_date,
                    'shipping_window_end_date' => $shipping_window_end_date,
                    'shipping_window_method_keys' => np_order_hub_normalize_shipping_method_keys($shipping_window_method_keys),
                    'shipping_window_include_postnord_parcel_locker' => $shipping_window_include_postnord,
                );
                echo '<div class="error"><p>' . esc_html($upsert->get_error_message()) . '</p></div>';
            } else {
                $stores = np_order_hub_get_stores();
                $edit_store = $upsert;
                $sync_result = np_order_hub_push_shipping_config_to_store($upsert);
                if (is_wp_error($sync_result)) {
                    echo '<div class="notice notice-warning"><p>Store updated, men fraktvindu ble ikke synket: ' . esc_html($sync_result->get_error_message()) . '</p></div>';
                } else {
                    echo '<div class="updated"><p>Store updated.</p></div>';
                }
            }
        }
    }

    if (!empty($_POST['np_order_hub_add_store'])) {
        check_admin_referer('np_order_hub_add_store');
        $key = sanitize_key((string) $_POST['store_key']);
        $name = sanitize_text_field((string) $_POST['store_name']);
        $url = esc_url_raw((string) $_POST['store_url']);
        $secret = trim((string) $_POST['store_secret']);
        $token = sanitize_text_field((string) $_POST['store_token']);
        $consumer_key = sanitize_text_field((string) ($_POST['store_consumer_key'] ?? ''));
        $consumer_secret = sanitize_text_field((string) ($_POST['store_consumer_secret'] ?? ''));
        $packing_slip_url = np_order_hub_sanitize_url_template((string) ($_POST['packing_slip_url'] ?? ''));
        $type = sanitize_key((string) $_POST['order_url_type']);
        $type = $type === 'hpos' ? 'hpos' : 'legacy';
        $delivery_bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? ''));
        $switch_date_raw = sanitize_text_field((string) ($_POST['delivery_bucket_switch_date'] ?? ''));
        $delivery_bucket_switch_date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date_raw) ? $switch_date_raw : '';
        $delivery_bucket_after = np_order_hub_normalize_delivery_bucket_optional((string) ($_POST['delivery_bucket_after'] ?? ''));
        $shipping_window_enabled = !empty($_POST['shipping_window_enabled']) ? '1' : '0';
        $shipping_window_start_date = sanitize_text_field((string) ($_POST['shipping_window_start_date'] ?? ''));
        $shipping_window_end_date = sanitize_text_field((string) ($_POST['shipping_window_end_date'] ?? ''));
        $shipping_window_method_keys = (string) ($_POST['shipping_window_method_keys'] ?? '');
        $shipping_window_include_postnord = !empty($_POST['shipping_window_include_postnord_parcel_locker']) ? '1' : '0';

        $upsert = np_order_hub_store_upsert(array(
            'key' => $key,
            'name' => $name,
            'url' => $url,
            'secret' => $secret,
            'token' => $token,
            'consumer_key' => $consumer_key,
            'consumer_secret' => $consumer_secret,
            'packing_slip_url' => $packing_slip_url,
            'order_url_type' => $type,
            'delivery_bucket' => $delivery_bucket,
            'delivery_bucket_switch_date' => $delivery_bucket_switch_date,
            'delivery_bucket_after' => $delivery_bucket_after,
            'shipping_window_enabled' => $shipping_window_enabled,
            'shipping_window_start_date' => $shipping_window_start_date,
            'shipping_window_end_date' => $shipping_window_end_date,
            'shipping_window_method_keys' => $shipping_window_method_keys,
            'shipping_window_include_postnord_parcel_locker' => $shipping_window_include_postnord,
        ));

        if (is_wp_error($upsert)) {
            echo '<div class="error"><p>' . esc_html($upsert->get_error_message()) . '</p></div>';
        } else {
            $stores = np_order_hub_get_stores();
            $sync_result = np_order_hub_push_shipping_config_to_store($upsert);
            if (is_wp_error($sync_result)) {
                echo '<div class="notice notice-warning"><p>Store saved, men fraktvindu ble ikke synket: ' . esc_html($sync_result->get_error_message()) . '</p></div>';
            } else {
                echo '<div class="updated"><p>Store saved.</p></div>';
            }
        }
    }

    if (!empty($_GET['action']) && $_GET['action'] === 'delete_store' && !empty($_GET['store'])) {
        check_admin_referer('np_order_hub_delete_store');
        $store_key = sanitize_key((string) $_GET['store']);
        if (isset($stores[$store_key])) {
            unset($stores[$store_key]);
            np_order_hub_save_stores($stores);
            echo '<div class="updated"><p>Store removed.</p></div>';
        }
    }

    if ($edit_store === null && !empty($_GET['action']) && $_GET['action'] === 'edit_store' && !empty($_GET['store'])) {
        $store_key = sanitize_key((string) $_GET['store']);
        if (isset($stores[$store_key]) && is_array($stores[$store_key])) {
            $edit_store = $stores[$store_key];
        }
    }

    $webhook_base = rest_url('np-order-hub/v1/webhook');

    echo '<div class="wrap">';
    echo '<h1>Order Hub Stores</h1>';

    echo '<h2>Connector setup</h2>';
    echo '<p>Use this key in school network to auto-connect stores to Order Hub.</p>';
    echo '<form method="post" style="margin:12px 0 24px;">';
    wp_nonce_field('np_order_hub_connector_setup_key');
    echo '<input type="text" name="np_order_hub_connector_setup_key" class="regular-text" value="' . esc_attr($connector_setup_key) . '" />';
    echo '<button type="submit" class="button button-primary" name="np_order_hub_connector_setup_action" value="save" style="margin-left:8px;">Save key</button>';
    echo '<button type="submit" class="button" name="np_order_hub_connector_setup_action" value="regenerate" style="margin-left:8px;">Regenerate key</button>';
    echo '<p class="description">Endpoint: <code>' . esc_html(rest_url('np-order-hub/v1/store-connect')) . '</code></p>';
    echo '</form>';

    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Store</th>';
    echo '<th>Key</th>';
    echo '<th>URL</th>';
    echo '<th>Order URL Type</th>';
    echo '<th>Default Delivery</th>';
    echo '<th>Token</th>';
    echo '<th>API</th>';
    echo '<th>Webhook URL</th>';
    echo '<th>Actions</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($stores)) {
        echo '<tr><td colspan="9">No stores added yet.</td></tr>';
    } else {
        foreach ($stores as $store) {
            if (!is_array($store)) {
                continue;
            }
            $edit_url = admin_url('admin.php?page=np-order-hub-stores&action=edit_store&store=' . urlencode($store['key']));
            $delete_url = wp_nonce_url(
                admin_url('admin.php?page=np-order-hub-stores&action=delete_store&store=' . urlencode($store['key'])),
                'np_order_hub_delete_store'
            );
            $webhook_url = add_query_arg('store', $store['key'], $webhook_base);
            echo '<tr>';
            echo '<td>' . esc_html($store['name']) . '</td>';
            echo '<td>' . esc_html($store['key']) . '</td>';
            echo '<td><a href="' . esc_url($store['url']) . '" target="_blank" rel="noopener">' . esc_html($store['url']) . '</a></td>';
            echo '<td>' . esc_html($store['order_url_type'] === 'hpos' ? 'HPOS' : 'Legacy') . '</td>';
            $store_bucket = isset($store['delivery_bucket']) ? np_order_hub_normalize_delivery_bucket($store['delivery_bucket']) : 'standard';
            $bucket_label = $store_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
            $switch_date = isset($store['delivery_bucket_switch_date']) ? (string) $store['delivery_bucket_switch_date'] : '';
            $bucket_note = '';
            if ($switch_date !== '') {
                $after_bucket = isset($store['delivery_bucket_after']) ? np_order_hub_normalize_delivery_bucket_optional($store['delivery_bucket_after']) : '';
                if ($after_bucket === '') {
                    $after_bucket = $store_bucket === 'standard' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
                }
                $after_label = $after_bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? 'Levering til bestemt dato' : 'Levering 3-5 dager';
                $bucket_note = ' (etter ' . $switch_date . ' → ' . $after_label . ')';
            }
            $shipping_window = np_order_hub_get_store_shipping_window($store);
            $shipping_note = '';
            if (!empty($shipping_window['shipping_window_enabled'])) {
                $range_parts = array();
                if (!empty($shipping_window['shipping_window_start_date'])) {
                    $range_parts[] = 'fra ' . $shipping_window['shipping_window_start_date'];
                }
                if (!empty($shipping_window['shipping_window_end_date'])) {
                    $range_parts[] = 'til ' . $shipping_window['shipping_window_end_date'];
                }
                $range_label = !empty($range_parts) ? implode(' ', $range_parts) : 'alltid';
                $method_parts = !empty($shipping_window['shipping_window_method_keys'])
                    ? array_slice((array) $shipping_window['shipping_window_method_keys'], 0, 3)
                    : array();
                if (!empty($shipping_window['shipping_window_include_postnord_parcel_locker'])) {
                    $method_parts[] = 'postnord_parcel_locker';
                }
                $method_label = !empty($method_parts)
                    ? implode(', ', $method_parts)
                    : 'ingen metoder valgt';
                $shipping_note = ' | Fraktvindu: ' . $range_label . ' (' . $method_label . ')';
            }
            echo '<td>' . esc_html($bucket_label . $bucket_note . $shipping_note) . '</td>';
            $token_label = !empty($store['token']) ? 'Configured' : '—';
            echo '<td>' . esc_html($token_label) . '</td>';
            $api_label = (!empty($store['consumer_key']) && !empty($store['consumer_secret'])) ? 'Configured' : '—';
            echo '<td>' . esc_html($api_label) . '</td>';
            echo '<td><code>' . esc_html($webhook_url) . '</code></td>';
            echo '<td><a class="button button-small" href="' . esc_url($edit_url) . '">Edit</a> <a class="button button-small" href="' . esc_url($delete_url) . '" onclick="return confirm(\'Remove this store?\')">Remove</a></td>';
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';

    $editing = is_array($edit_store);
    $store_key_value = $editing && isset($edit_store['key']) ? (string) $edit_store['key'] : '';
    $store_name_value = $editing && isset($edit_store['name']) ? (string) $edit_store['name'] : '';
    $store_url_value = $editing && isset($edit_store['url']) ? (string) $edit_store['url'] : '';
    $store_secret_value = $editing && isset($edit_store['secret']) ? (string) $edit_store['secret'] : '';
    $store_token_value = $editing && isset($edit_store['token']) ? (string) $edit_store['token'] : '';
    $store_consumer_key_value = $editing && isset($edit_store['consumer_key']) ? (string) $edit_store['consumer_key'] : '';
    $store_consumer_secret_value = $editing && isset($edit_store['consumer_secret']) ? (string) $edit_store['consumer_secret'] : '';
    $order_url_type_value = $editing && !empty($edit_store['order_url_type']) ? (string) $edit_store['order_url_type'] : NP_ORDER_HUB_DEFAULT_ORDER_URL_TYPE;
    $order_url_type_value = $order_url_type_value === 'hpos' ? 'hpos' : 'legacy';
    $delivery_bucket_value = $editing && isset($edit_store['delivery_bucket']) ? (string) $edit_store['delivery_bucket'] : 'standard';
    $delivery_bucket_value = np_order_hub_normalize_delivery_bucket($delivery_bucket_value);
    $delivery_bucket_switch_date_value = $editing && isset($edit_store['delivery_bucket_switch_date']) ? (string) $edit_store['delivery_bucket_switch_date'] : '';
    $delivery_bucket_after_value = $editing && isset($edit_store['delivery_bucket_after']) ? (string) $edit_store['delivery_bucket_after'] : '';
    $delivery_bucket_after_value = np_order_hub_normalize_delivery_bucket_optional($delivery_bucket_after_value);
    $shipping_window_enabled_value = $editing && !empty($edit_store['shipping_window_enabled']);
    $shipping_window_start_date_value = $editing && isset($edit_store['shipping_window_start_date']) ? (string) $edit_store['shipping_window_start_date'] : '';
    $shipping_window_end_date_value = $editing && isset($edit_store['shipping_window_end_date']) ? (string) $edit_store['shipping_window_end_date'] : '';
    $shipping_window_method_keys_value = $editing && isset($edit_store['shipping_window_method_keys'])
        ? np_order_hub_shipping_method_keys_to_text($edit_store['shipping_window_method_keys'])
        : '';
    $shipping_window_include_postnord_value = $editing && !empty($edit_store['shipping_window_include_postnord_parcel_locker']);

    echo '<h2>' . esc_html($editing ? 'Edit Store' : 'Add Store') . '</h2>';
    if ($editing) {
        $cancel_url = admin_url('admin.php?page=np-order-hub-stores');
        echo '<p><a class="button" href="' . esc_url($cancel_url) . '">Cancel edit</a></p>';
    }
    echo '<form method="post">';
    wp_nonce_field($editing ? 'np_order_hub_update_store' : 'np_order_hub_add_store');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="store_key">Store Key</label></th>';
    echo '<td><input name="store_key" id="store_key" type="text" class="regular-text" value="' . esc_attr($store_key_value) . '"' . ($editing ? ' readonly' : '') . ' required />';
    echo $editing ? ' <p class="description">Store key cannot be changed.</p>' : ' <p class="description">Short ID like butikk1.</p>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="store_name">Store Name</label></th>';
    echo '<td><input name="store_name" id="store_name" type="text" class="regular-text" value="' . esc_attr($store_name_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_url">Store URL</label></th>';
    echo '<td><input name="store_url" id="store_url" type="url" class="regular-text" value="' . esc_attr($store_url_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_secret">Webhook Secret</label></th>';
    echo '<td><input name="store_secret" id="store_secret" type="text" class="regular-text" value="' . esc_attr($store_secret_value) . '" required /></td></tr>';
    echo '<tr><th scope="row"><label for="store_token">Store Token</label></th>';
    echo '<td><input name="store_token" id="store_token" type="text" class="regular-text" value="' . esc_attr($store_token_value) . '" />';
    echo '<p class="description">Token from the store plugin (Order Hub Packing Slip page).</p></td></tr>';
    echo '<tr><th scope="row"><label for="store_consumer_key">WooCommerce API Key</label></th>';
    echo '<td><input name="store_consumer_key" id="store_consumer_key" type="text" class="regular-text" value="' . esc_attr($store_consumer_key_value) . '" />';
    echo '<p class="description">Consumer key with read permissions.</p></td></tr>';
    echo '<tr><th scope="row"><label for="store_consumer_secret">WooCommerce API Secret</label></th>';
    echo '<td><input name="store_consumer_secret" id="store_consumer_secret" type="text" class="regular-text" value="' . esc_attr($store_consumer_secret_value) . '" />';
    echo '<p class="description">Consumer secret for revenue import.</p></td></tr>';
    echo '<tr><th scope="row"><label for="order_url_type">Order URL Type</label></th>';
    echo '<td><select name="order_url_type" id="order_url_type">';
    echo '<option value="legacy"' . selected($order_url_type_value, 'legacy', false) . '>Legacy (post.php)</option>';
    echo '<option value="hpos"' . selected($order_url_type_value, 'hpos', false) . '>HPOS (wc-orders)</option>';
    echo '</select></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket">Default Delivery</label></th>';
    echo '<td><select name="delivery_bucket" id="delivery_bucket">';
    echo '<option value="standard"' . selected($delivery_bucket_value, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket_value, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p class="description">Used to place new orders in the correct dashboard automatically.</p></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket_switch_date">Bytt etter dato</label></th>';
    echo '<td><input name="delivery_bucket_switch_date" id="delivery_bucket_switch_date" type="date" class="regular-text" value="' . esc_attr($delivery_bucket_switch_date_value) . '" />';
    echo '<p class="description">Default gjelder til og med valgt dato. Fra dagen etter brukes "Bytt til".</p></td></tr>';
    echo '<tr><th scope="row"><label for="delivery_bucket_after">Bytt til</label></th>';
    echo '<td><select name="delivery_bucket_after" id="delivery_bucket_after">';
    echo '<option value=""' . selected($delivery_bucket_after_value, '', false) . '>Ingen endring</option>';
    echo '<option value="standard"' . selected($delivery_bucket_after_value, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket_after_value, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p class="description">Valgfritt. Hvis tomt, bytter vi til motsatt av default.</p></td></tr>';
    echo '<tr><th scope="row"><label for="shipping_window_enabled">Datostyrte fraktvalg</label></th>';
    echo '<td><label><input type="checkbox" name="shipping_window_enabled" id="shipping_window_enabled" value="1"' . checked($shipping_window_enabled_value, true, false) . ' /> Aktiver fraktvindu fra hub</label>';
    echo '<p class="description">Når aktiv: metodene under vises kun i valgt datoperiode. Utenfor perioden skjules disse metodene, og øvrige fraktmetoder brukes.</p></td></tr>';
    echo '<tr><th scope="row"><label for="shipping_window_start_date">Fraktvindu start</label></th>';
    echo '<td><input name="shipping_window_start_date" id="shipping_window_start_date" type="date" class="regular-text" value="' . esc_attr($shipping_window_start_date_value) . '" />';
    echo '<p class="description">Valgfritt. Tom = ingen nedre grense.</p></td></tr>';
    echo '<tr><th scope="row"><label for="shipping_window_end_date">Fraktvindu slutt</label></th>';
    echo '<td><input name="shipping_window_end_date" id="shipping_window_end_date" type="date" class="regular-text" value="' . esc_attr($shipping_window_end_date_value) . '" />';
    echo '<p class="description">Valgfritt. Tom = ingen øvre grense.</p></td></tr>';
    echo '<tr><th scope="row"><label for="shipping_window_method_keys">Fraktmetoder i fraktvindu</label></th>';
    echo '<td><textarea name="shipping_window_method_keys" id="shipping_window_method_keys" rows="4" class="large-text code">' . esc_textarea($shipping_window_method_keys_value) . '</textarea>';
    echo '<p class="description">Én metode per linje, f.eks. <code>local_pickup:4</code> eller <code>flat_rate:2</code>. Bruk eksakt metode-ID fra butikken.</p></td></tr>';
    echo '<tr><th scope="row"><label for="shipping_window_include_postnord_parcel_locker">Postnord Parcel locker</label></th>';
    echo '<td><label><input type="checkbox" name="shipping_window_include_postnord_parcel_locker" id="shipping_window_include_postnord_parcel_locker" value="1"' . checked($shipping_window_include_postnord_value, true, false) . ' /> Behandle Postnord Parcel locker som metode i fraktvindu</label>';
    echo '<p class="description">Når huket av følger Postnord Parcel locker samme regler som "Hente på skolen" i datostyrt fraktvindu.</p></td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="' . esc_attr($editing ? 'np_order_hub_update_store' : 'np_order_hub_add_store') . '" value="1">' . esc_html($editing ? 'Update Store' : 'Save Store') . '</button></p>';
    echo '</form>';

    echo '</div>';
}
