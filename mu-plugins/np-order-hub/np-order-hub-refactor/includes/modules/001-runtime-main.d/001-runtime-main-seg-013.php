<?php
function np_order_hub_query_reklamasjon_orders($filters, $limit = 100) {
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

    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";

    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}

function np_order_hub_query_restordre_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);

    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";

    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_restordre_totals($filters, $start_gmt = '', $end_gmt = '') {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
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

function np_order_hub_query_restordre_orders($filters, $limit = 100) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = 'restordre';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);

    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";

    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}

function np_order_hub_get_bytte_storrelse_like() {
    global $wpdb;
    $needle = '"np_bytte_storrelse":true';
    return '%' . $wpdb->esc_like($needle) . '%';
}

function np_order_hub_query_bytte_storrelse_by_store($filters) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $bytte_sql = '(payload LIKE %s OR status = %s)';
    $args[] = np_order_hub_get_bytte_storrelse_like();
    $args[] = 'bytte-storrelse';
    $where = $where ? ($where . ' AND ' . $bytte_sql) : ('WHERE ' . $bytte_sql);

    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS count, COALESCE(SUM(total), 0) AS total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";

    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_bytte_storrelse_totals($filters, $start_gmt = '', $end_gmt = '') {
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

    $bytte_sql = '(payload LIKE %s OR status = %s)';
    $args[] = np_order_hub_get_bytte_storrelse_like();
    $args[] = 'bytte-storrelse';
    $where = $where ? ($where . ' AND ' . $bytte_sql) : ('WHERE ' . $bytte_sql);

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

function np_order_hub_query_bytte_storrelse_orders($filters, $limit = 100) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $args = array();
    $filters = is_array($filters) ? $filters : array();
    $filters['status'] = '';
    $filters['search'] = '';

    $where = np_order_hub_build_where_clause($filters, $args, false, true);
    $bytte_sql = '(payload LIKE %s OR status = %s)';
    $args[] = np_order_hub_get_bytte_storrelse_like();
    $args[] = 'bytte-storrelse';
    $where = $where ? ($where . ' AND ' . $bytte_sql) : ('WHERE ' . $bytte_sql);

    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";

    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}

function np_order_hub_build_produksjonsfeil_where_clause($filters, &$args) {
    global $wpdb;
    $where = array();

	if (!empty($filters['store'])) {
	        $where[] = 'store_key = %s';
	        $args[] = sanitize_key((string) $filters['store']);
	    }
	    if (!empty($filters['error_type'])) {
	        $where[] = 'error_type = %s';
	        $args[] = np_order_hub_normalize_production_error_type((string) $filters['error_type']);
	    }
	    if (!empty($filters['date_from'])) {
	        $where[] = 'created_at_gmt >= %s';
	        $args[] = (string) $filters['date_from'];
    }
    if (!empty($filters['date_to'])) {
        $where[] = 'created_at_gmt <= %s';
        $args[] = (string) $filters['date_to'];
    }
    if (!empty($filters['search'])) {
        $like = '%' . $wpdb->esc_like((string) $filters['search']) . '%';
        $where[] = '(product_name LIKE %s OR sku LIKE %s OR size_label LIKE %s OR note LIKE %s)';
        $args[] = $like;
        $args[] = $like;
        $args[] = $like;
        $args[] = $like;
    }

    if (empty($where)) {
        return '';
    }
    return 'WHERE ' . implode(' AND ', $where);
}

function np_order_hub_query_produksjonsfeil_totals($filters) {
    np_order_hub_ensure_production_error_table();

    global $wpdb;
    $table = np_order_hub_production_error_table_name();
    $args = array();
    $where = np_order_hub_build_produksjonsfeil_where_clause(is_array($filters) ? $filters : array(), $args);
    $sql = "SELECT COUNT(*) AS rows_count, COALESCE(SUM(quantity), 0) AS qty_total, COALESCE(SUM(total_cost), 0) AS cost_total FROM $table $where";
    $row = $args ? $wpdb->get_row($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_row($sql, ARRAY_A);
    if (!is_array($row)) {
        return array('rows_count' => 0, 'qty_total' => 0, 'cost_total' => 0.0);
    }
    return array(
        'rows_count' => (int) $row['rows_count'],
        'qty_total' => (int) $row['qty_total'],
        'cost_total' => (float) $row['cost_total'],
    );
}

function np_order_hub_query_produksjonsfeil_by_store($filters) {
    np_order_hub_ensure_production_error_table();

    global $wpdb;
    $table = np_order_hub_production_error_table_name();
    $args = array();
    $where = np_order_hub_build_produksjonsfeil_where_clause(is_array($filters) ? $filters : array(), $args);
    $sql = "SELECT store_key, store_name, currency, COUNT(*) AS rows_count, COALESCE(SUM(quantity), 0) AS qty_total, COALESCE(SUM(total_cost), 0) AS cost_total
        FROM $table $where
        GROUP BY store_key, store_name, currency
        ORDER BY store_name, store_key";
    return $args ? $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
}

function np_order_hub_query_produksjonsfeil_rows($filters, $limit = 500) {
    np_order_hub_ensure_production_error_table();

    global $wpdb;
    $table = np_order_hub_production_error_table_name();
    $args = array();
    $where = np_order_hub_build_produksjonsfeil_where_clause(is_array($filters) ? $filters : array(), $args);
    $limit = max(1, (int) $limit);
    $args[] = $limit;
    $sql = "SELECT * FROM $table $where ORDER BY created_at_gmt DESC, id DESC LIMIT %d";
    return $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
}