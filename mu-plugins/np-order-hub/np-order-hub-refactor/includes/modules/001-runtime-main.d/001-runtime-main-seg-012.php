<?php
function np_order_hub_get_reklamasjon_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => '',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_restordre_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => 'restordre',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_bytte_storrelse_filters() {
    $filters = array(
        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
        'status' => '',
        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
        'search' => '',
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
    return $filters;
}

function np_order_hub_get_produksjonsfeil_filters() {
	$view_raw = isset($_GET['view']) ? sanitize_key((string) $_GET['view']) : '';
	if ($view_raw === '' && isset($_GET['error_type'])) {
		$view_raw = sanitize_key((string) $_GET['error_type']);
	}
	if ($view_raw === '') {
		$view_raw = 'trykkfeil';
	}
	$error_type = np_order_hub_normalize_production_error_type($view_raw);

	    $filters = array(
	        'store' => isset($_GET['store']) ? sanitize_key((string) $_GET['store']) : '',
	        'date_from_raw' => isset($_GET['date_from']) ? sanitize_text_field((string) $_GET['date_from']) : '',
	        'date_to_raw' => isset($_GET['date_to']) ? sanitize_text_field((string) $_GET['date_to']) : '',
	        'search' => isset($_GET['s']) ? sanitize_text_field((string) $_GET['s']) : '',
	        'error_type' => $error_type,
	    );
	    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
	    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);
	    return $filters;
}

function np_order_hub_build_where_clause($filters, &$args, $include_search = true, $include_dates = true) {
    global $wpdb;
    $where = array();

    if (!empty($filters['store'])) {
        $where[] = 'store_key = %s';
        $args[] = $filters['store'];
    }
    if (!empty($filters['status'])) {
        $where[] = 'status = %s';
        $args[] = $filters['status'];
    }
    if ($include_dates) {
        if (!empty($filters['date_from'])) {
            $where[] = 'date_created_gmt >= %s';
            $args[] = $filters['date_from'];
        }
        if (!empty($filters['date_to'])) {
            $where[] = 'date_created_gmt <= %s';
            $args[] = $filters['date_to'];
        }
    }
    if ($include_search && !empty($filters['search'])) {
        $search = $filters['search'];
        $like = '%' . $wpdb->esc_like($search) . '%';
        if (is_numeric($search)) {
            $where[] = '(order_id = %d OR order_number LIKE %s)';
            $args[] = (int) $search;
            $args[] = $like;
        } else {
            $where[] = 'order_number LIKE %s';
            $args[] = $like;
        }
    }

    if (empty($where)) {
        return '';
    }
    return 'WHERE ' . implode(' AND ', $where);
}

function np_order_hub_normalize_delivery_bucket($bucket) {
    $bucket = sanitize_key((string) $bucket);
    return $bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
}

function np_order_hub_normalize_delivery_bucket_optional($bucket) {
    $bucket = sanitize_key((string) $bucket);
    if ($bucket === '') {
        return '';
    }
    return np_order_hub_normalize_delivery_bucket($bucket);
}

function np_order_hub_get_active_store_delivery_bucket($store) {
    $default_bucket = isset($store['delivery_bucket']) ? np_order_hub_normalize_delivery_bucket($store['delivery_bucket']) : 'standard';
    $switch_date = isset($store['delivery_bucket_switch_date']) ? trim((string) $store['delivery_bucket_switch_date']) : '';
    $switch_bucket = isset($store['delivery_bucket_after']) ? np_order_hub_normalize_delivery_bucket_optional($store['delivery_bucket_after']) : '';

    if ($switch_date !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $switch_date)) {
        $today = current_time('Y-m-d');
        // "Bytt dato" tolkes som "gjelder til og med denne datoen".
        // Bytte skjer fra og med dagen etter.
        if ($today > $switch_date) {
            if ($switch_bucket === '') {
                $switch_bucket = $default_bucket === 'standard' ? NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED : 'standard';
            }
            return $switch_bucket;
        }
    }

    return $default_bucket;
}

function np_order_hub_get_delivery_bucket_like() {
    global $wpdb;
    $needle = '"' . NP_ORDER_HUB_DELIVERY_BUCKET_KEY . '":"' . NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED . '"';
    return '%' . $wpdb->esc_like($needle) . '%';
}

function np_order_hub_add_delivery_bucket_where($where, &$args, $bucket) {
    $bucket = np_order_hub_normalize_delivery_bucket($bucket);
    $like = np_order_hub_get_delivery_bucket_like();
    if ($bucket === NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED) {
        $clause = 'payload LIKE %s';
        $args[] = $like;
    } else {
        $clause = "(payload NOT LIKE %s OR payload IS NULL OR payload = '')";
        $args[] = $like;
    }
    return $where ? ($where . ' AND ' . $clause) : ('WHERE ' . $clause);
}

function np_order_hub_extract_delivery_bucket_from_payload_data($payload) {
    if (is_string($payload) && $payload !== '') {
        $decoded = json_decode($payload, true);
        if (is_array($decoded)) {
            $payload = $decoded;
        }
    }
    if (!is_array($payload)) {
        return '';
    }
    if (!array_key_exists(NP_ORDER_HUB_DELIVERY_BUCKET_KEY, $payload)) {
        return '';
    }
    return np_order_hub_normalize_delivery_bucket($payload[NP_ORDER_HUB_DELIVERY_BUCKET_KEY]);
}

function np_order_hub_query_metric_range($filters, $start_gmt = '', $end_gmt = '', $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, false);

    $range = array();
    if ($start_gmt !== '') {
        $range[] = 'date_created_gmt >= %s';
        $args[] = $start_gmt;
    }
    if ($end_gmt !== '') {
        $range[] = 'date_created_gmt <= %s';
        $args[] = $end_gmt;
    }
    if (!empty($range)) {
        $range_sql = implode(' AND ', $range);
        $where = $where ? ($where . ' AND ' . $range_sql) : ('WHERE ' . $range_sql);
    }

    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);

    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}

function np_order_hub_get_currency_label($filters, $delivery_bucket = 'standard') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $where = np_order_hub_build_where_clause($filters, $args, false, false);
    $where = np_order_hub_add_delivery_bucket_where($where, $args, $delivery_bucket);
    $currency_where = $where ? ($where . " AND currency <> ''") : "WHERE currency <> ''";
    $sql = "SELECT DISTINCT currency FROM $table $currency_where LIMIT 2";
    $currencies = $args ? $wpdb->get_col($wpdb->prepare($sql, $args)) : $wpdb->get_col($sql);
    if (is_array($currencies) && count($currencies) === 1) {
        return (string) $currencies[0];
    }
    return '';
}

function np_order_hub_get_reklamasjon_like() {
    global $wpdb;
    $needle = '"np_reklamasjon":true';
    return '%' . $wpdb->esc_like($needle) . '%';
}

function np_order_hub_query_reklamasjon_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $reklamasjon_sql = "(payload LIKE %s OR status = %s)";
    $args[] = np_order_hub_get_reklamasjon_like();
    $args[] = 'reklamasjon';
    $where = $where ? ($where . ' AND ' . $reklamasjon_sql) : ('WHERE ' . $reklamasjon_sql);

    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";

    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_reklamasjon_totals($filters, $start_gmt = '', $end_gmt = '') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, false);

    $range = array();
    if ($start_gmt !== '') {
        $range[] = 'date_created_gmt >= %s';
        $args[] = $start_gmt;
    }
    if ($end_gmt !== '') {
        $range[] = 'date_created_gmt <= %s';
        $args[] = $end_gmt;
    }
    if (!empty($range)) {
        $range_sql = implode(' AND ', $range);
        $where = $where ? ($where . ' AND ' . $range_sql) : ('WHERE ' . $range_sql);
    }

    $reklamasjon_sql = "(payload LIKE %s OR status = %s)";
    $args[] = np_order_hub_get_reklamasjon_like();
    $args[] = 'reklamasjon';
    $where = $where ? ($where . ' AND ' . $reklamasjon_sql) : ('WHERE ' . $reklamasjon_sql);

    $sql = "SELECT COUNT(*) AS count, COALESCE(SUM(total), 0) AS total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('count' => 0, 'total' => 0.0);
    }
    return array(
        'count' => (int) $row['count'],
        'total' => (float) $row['total'],
    );
}