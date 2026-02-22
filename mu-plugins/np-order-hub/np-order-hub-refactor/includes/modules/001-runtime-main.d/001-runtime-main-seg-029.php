<?php
if (is_admin()) {
    if (!class_exists('WP_List_Table')) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
    }

    class NP_Order_Hub_Orders_Table extends WP_List_Table {
    public function get_columns() {
        return array(
            'store' => 'Store',
            'order' => 'Order',
            'customer' => 'Customer',
            'date' => 'Date',
            'status' => 'Status',
            'reklamasjon' => 'Reklamasjon',
            'total' => 'Total',
            'actions' => '',
        );
    }

    protected function get_sortable_columns() {
        return array(
            'store' => array('store_name', false),
            'date' => array('date_created_gmt', true),
            'status' => array('status', false),
            'total' => array('total', false),
        );
    }

    public function column_store($item) {
        $name = isset($item['store_name']) ? $item['store_name'] : '';
        $url = isset($item['store_url']) ? $item['store_url'] : '';
        if ($url !== '') {
            return '<strong>' . esc_html($name) . '</strong><br /><span class="description">' . esc_html($url) . '</span>';
        }
        return esc_html($name);
    }

    public function column_order($item) {
        $number = isset($item['order_number']) ? $item['order_number'] : '';
        $order_id = isset($item['order_id']) ? (int) $item['order_id'] : 0;
        $label = $number !== '' ? ('#' . $number) : ('#' . $order_id);
        $url = isset($item['order_admin_url']) ? $item['order_admin_url'] : '';
        if ($url !== '') {
            return '<a href="' . esc_url($url) . '" target="_blank" rel="noopener">' . esc_html($label) . '</a>';
        }
        return esc_html($label);
    }

    public function column_customer($item) {
        return esc_html(np_order_hub_get_customer_label($item));
    }

    public function column_date($item) {
        $gmt = isset($item['date_created_gmt']) ? $item['date_created_gmt'] : '';
        if ($gmt === '' || $gmt === '0000-00-00 00:00:00') {
            return '';
        }
        $local = get_date_from_gmt($gmt, 'd.m.y');
        return esc_html($local);
    }

    public function column_status($item) {
        $status = isset($item['status']) ? $item['status'] : '';
        if ($status === '') {
            return '';
        }
        $label = ucwords(str_replace('-', ' ', $status));
        return esc_html($label);
    }

    public function column_reklamasjon($item) {
        return np_order_hub_record_is_reklamasjon($item) ? 'Ja' : '—';
    }

    public function column_total($item) {
        $total = isset($item['total']) ? (float) $item['total'] : 0.0;
        $currency = isset($item['currency']) ? $item['currency'] : '';
        $formatted = number_format_i18n($total, 2);
        $display = trim($formatted . ' ' . $currency);
        return esc_html($display);
    }

    public function column_actions($item) {
        $actions = array();
        $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $item['id']);
        $actions[] = '<a class="button button-small" href="' . esc_url($details_url) . '">Details</a>';

        $store = np_order_hub_get_store_by_key(isset($item['store_key']) ? $item['store_key'] : '');
        $packing_url = np_order_hub_build_packing_slip_url(
            $store,
            isset($item['order_id']) ? (int) $item['order_id'] : 0,
            isset($item['order_number']) ? (string) $item['order_number'] : '',
            isset($item['payload']) ? $item['payload'] : null
        );
        if ($packing_url !== '') {
            $actions[] = '<a class="button button-small" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
        }

        $url = isset($item['order_admin_url']) ? $item['order_admin_url'] : '';
        if ($url !== '') {
            $actions[] = '<a class="button button-small" href="' . esc_url($url) . '" target="_blank" rel="noopener">Open order</a>';
        }
        return implode(' ', $actions);
    }

    public function prepare_items() {
        global $wpdb;
        $table = np_order_hub_table_name();

        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();
        $this->_column_headers = array($columns, $hidden, $sortable);

        $orderby = isset($_GET['orderby']) ? sanitize_key((string) $_GET['orderby']) : 'date_created_gmt';
        $order = isset($_GET['order']) ? strtoupper((string) $_GET['order']) : 'DESC';

        $allowed_orderby = array('store_name', 'date_created_gmt', 'status', 'total');
        if (!in_array($orderby, $allowed_orderby, true)) {
            $orderby = 'date_created_gmt';
        }
        $order = $order === 'ASC' ? 'ASC' : 'DESC';

        $per_page = NP_ORDER_HUB_PER_PAGE;
        $current_page = $this->get_pagenum();
        $offset = ($current_page - 1) * $per_page;

        $total_items = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table");

        $items = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table ORDER BY $orderby $order LIMIT %d OFFSET %d",
                $per_page,
                $offset
            ),
            ARRAY_A
        );

        $this->items = $items;

        $this->set_pagination_args(array(
            'total_items' => $total_items,
            'per_page' => $per_page,
            'total_pages' => $per_page > 0 ? ceil($total_items / $per_page) : 1,
        ));
    }
    }
}
