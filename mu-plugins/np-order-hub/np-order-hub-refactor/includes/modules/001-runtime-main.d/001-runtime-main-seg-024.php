<?php
function np_order_hub_notifications_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $notice = '';
    if (!empty($_POST['np_order_hub_save_notifications']) && check_admin_referer('np_order_hub_save_notifications')) {
        $enabled = !empty($_POST['np_order_hub_pushover_enabled']);
        $user_key = sanitize_text_field((string) ($_POST['np_order_hub_pushover_user'] ?? ''));
        $token = sanitize_text_field((string) ($_POST['np_order_hub_pushover_token'] ?? ''));
        $title = sanitize_text_field((string) ($_POST['np_order_hub_pushover_title'] ?? 'Order Hub'));
        $logo_enabled = !empty($_POST['np_order_hub_pushover_logo_enabled']);
        $logo_url = esc_url_raw((string) ($_POST['np_order_hub_pushover_logo'] ?? ''));

        update_option(NP_ORDER_HUB_PUSHOVER_ENABLED_OPTION, $enabled ? '1' : '0');
        update_option(NP_ORDER_HUB_PUSHOVER_USER_OPTION, $user_key);
        update_option(NP_ORDER_HUB_PUSHOVER_TOKEN_OPTION, $token);
        update_option(NP_ORDER_HUB_PUSHOVER_TITLE_OPTION, $title);
        update_option(NP_ORDER_HUB_PUSHOVER_LOGO_ENABLED_OPTION, $logo_enabled ? '1' : '0');
        update_option(NP_ORDER_HUB_PUSHOVER_LOGO_OPTION, $logo_url);
        $notice = 'Settings saved.';
    }

    $settings = np_order_hub_get_pushover_settings();

    echo '<div class="wrap">';
    echo '<h1>Varsler</h1>';
    if ($notice !== '') {
        echo '<div class="updated"><p>' . esc_html($notice) . '</p></div>';
    }
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_save_notifications');
    echo '<table class="form-table">';
    echo '<tr><th scope="row">Enable Pushover</th><td>';
    echo '<label><input type="checkbox" name="np_order_hub_pushover_enabled" value="1"' . checked($settings['enabled'], true, false) . ' /> Send notifications for new orders</label>';
    echo '</td></tr>';
    echo '<tr><th scope="row">Logo attachment</th><td>';
    echo '<label><input type="checkbox" name="np_order_hub_pushover_logo_enabled" value="1"' . checked(!empty($settings['logo_enabled']), true, false) . ' /> Attach logo image to push notifications</label>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-user">User key</label></th>';
    echo '<td><input id="np-order-hub-pushover-user" name="np_order_hub_pushover_user" type="text" class="regular-text" value="' . esc_attr($settings['user']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-token">App token</label></th>';
    echo '<td><input id="np-order-hub-pushover-token" name="np_order_hub_pushover_token" type="text" class="regular-text" value="' . esc_attr($settings['token']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-title">Title</label></th>';
    echo '<td><input id="np-order-hub-pushover-title" name="np_order_hub_pushover_title" type="text" class="regular-text" value="' . esc_attr($settings['title']) . '" />';
    echo '<p class="description">Set the Pushover application icon/logo in your Pushover app settings.</p>';
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-pushover-logo">Logo URL</label></th>';
    echo '<td><input id="np-order-hub-pushover-logo" name="np_order_hub_pushover_logo" type="url" class="regular-text" value="' . esc_attr($settings['logo_url']) . '" />';
    echo '<p class="description">Optional. Upload logo to Media Library and paste the URL. Leave blank to use the default Nordic logo.</p>';
    echo '</td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_save_notifications" value="1">Save settings</button></p>';
    echo '</form>';
    echo '</div>';
}

function np_order_hub_revenue_dashboard_shortcode($atts) {
    if (!defined('DONOTCACHEPAGE')) {
        define('DONOTCACHEPAGE', true);
    }
    if (!defined('DONOTCACHEOBJECT')) {
        define('DONOTCACHEOBJECT', true);
    }
    if (!defined('DONOTCACHEDB')) {
        define('DONOTCACHEDB', true);
    }
    if (!headers_sent()) {
        nocache_headers();
    }

    $atts = shortcode_atts(array(
        'capability' => 'manage_options',
        'refresh' => '',
        'private' => '0',
        'debug' => '0',
    ), $atts, 'np_order_hub_revenue_dashboard');

    $private_raw = strtolower(trim((string) $atts['private']));
    $require_auth = in_array($private_raw, array('1', 'true', 'yes', 'y', 'on'), true);
    $debug_raw = strtolower(trim((string) $atts['debug']));
    $debug_enabled = in_array($debug_raw, array('1', 'true', 'yes', 'y', 'on'), true);
    $capability = sanitize_key((string) $atts['capability']);
    if ($capability === '') {
        $capability = 'manage_options';
    }
    $can_view = true;
    if ($require_auth) {
        $can_view = current_user_can($capability);
    }
    if (!$can_view) {
        if ($debug_enabled) {
            $debug = array(
                'private_raw' => $private_raw,
                'require_auth' => $require_auth,
                'capability' => $capability,
                'is_user_logged_in' => is_user_logged_in(),
                'current_user_can' => $can_view,
                'time' => current_time('mysql'),
            );
            return '<pre class="np-order-hub-debug-box">' . esc_html(wp_json_encode($debug, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
        }
        return '<p>Ingen tilgang.</p>';
    }

    $period_input = isset($_GET['np_period']) ? $_GET['np_period'] : 'daily';
    $custom_from = isset($_GET['np_from']) ? $_GET['np_from'] : '';
    $custom_to = isset($_GET['np_to']) ? $_GET['np_to'] : '';
    $range = np_order_hub_get_period_date_range($period_input, $custom_from, $custom_to);
    $filters = array(
        'store' => '',
        'status' => '',
        'search' => '',
        'date_from_raw' => $range['from'],
        'date_to_raw' => $range['to'],
    );
    $filters['date_from'] = np_order_hub_get_date_gmt_from_input($filters['date_from_raw'], false);
    $filters['date_to'] = np_order_hub_get_date_gmt_from_input($filters['date_to_raw'], true);

    $rows = np_order_hub_query_revenue_by_store($filters);
    $totals = np_order_hub_query_revenue_totals($filters);
    $item_counts = np_order_hub_query_item_counts($filters);
    $items_by_store = isset($item_counts['by_store']) && is_array($item_counts['by_store']) ? $item_counts['by_store'] : array();

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

    $now = current_time('timestamp');
    $month_name = np_order_hub_get_norwegian_month_name($now);
    $prev_month_ts = strtotime('first day of last month', $now);
    $prev_month_name = np_order_hub_get_norwegian_month_name($prev_month_ts);
    $period_labels = array(
        'daily' => 'Daglig',
        'weekly' => 'Ukentlig',
        'month_current' => 'Denne måneden',
        'month_previous' => 'Forrige måned',
        'yearly' => 'Årlig',
        'custom' => 'Valgt periode',
    );
    $period_label = isset($period_labels[$range['period']]) ? $period_labels[$range['period']] : 'Daglig';

    $vat_mode_input = isset($_GET['np_vat_mode']) ? sanitize_key((string) wp_unslash($_GET['np_vat_mode'])) : 'ex';
    $vat_mode = $vat_mode_input === 'inc' ? 'inc' : 'ex';
    $is_inc_mode = $vat_mode === 'inc';

    $current_url = home_url(add_query_arg(array(), wp_unslash($_SERVER['REQUEST_URI'])));
    $base_url = remove_query_arg(array('np_period', 'np_from', 'np_to', 'np_vat_mode'), $current_url);
    $period_urls = array(
        'daily' => add_query_arg('np_period', 'daily', $base_url),
        'weekly' => add_query_arg('np_period', 'weekly', $base_url),
        'month_current' => add_query_arg('np_period', 'month_current', $base_url),
        'month_previous' => add_query_arg('np_period', 'month_previous', $base_url),
        'yearly' => add_query_arg('np_period', 'yearly', $base_url),
    );
    if ($vat_mode !== 'ex') {
        foreach ($period_urls as $period_key => $period_url) {
            $period_urls[$period_key] = add_query_arg('np_vat_mode', $vat_mode, $period_url);
        }
    }
    $vat_mode_urls = array(
        'ex' => add_query_arg(array('np_vat_mode' => 'ex'), $base_url),
        'inc' => add_query_arg(array('np_vat_mode' => 'inc'), $base_url),
    );
    foreach ($vat_mode_urls as $mode_key => $mode_url) {
        if ($range['period'] !== 'daily') {
            $mode_url = add_query_arg('np_period', $range['period'], $mode_url);
        }
        if ($range['period'] === 'custom') {
            if ($custom_from !== '') {
                $mode_url = add_query_arg('np_from', $custom_from, $mode_url);
            }
            if ($custom_to !== '') {
                $mode_url = add_query_arg('np_to', $custom_to, $mode_url);
            }
        }
        $vat_mode_urls[$mode_key] = $mode_url;
    }

    $refresh_seconds = is_numeric($atts['refresh']) ? (int) $atts['refresh'] : 0;
    if ($refresh_seconds < 0) {
        $refresh_seconds = 0;
    }
    $custom_from_value = $range['from'];
    $custom_to_value = $range['to'];

    ob_start();
    echo '<div class="np-order-hub-revenue-dashboard">';
    $period_links = array();
    $yearly_link = '';
    foreach ($period_urls as $key => $url) {
        $active = $range['period'] === $key ? ' is-active' : '';
        $label = isset($period_labels[$key]) ? $period_labels[$key] : $key;
        $link_html = '<a class="np-order-hub-period' . ($key === 'yearly' ? ' np-order-hub-period-yearly' : '') . $active . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
        if ($key === 'yearly') {
            $yearly_link = $link_html;
        } else {
            $period_links[] = $link_html;
        }
    }

    echo '<div class="np-order-hub-vat-toggle-row">';
    echo '<div class="np-order-hub-vat-toggle">';
    echo '<a class="np-order-hub-vat-mode' . ($vat_mode === 'ex' ? ' is-active' : '') . '" href="' . esc_url($vat_mode_urls['ex']) . '">Eks mva</a>';
    echo '<a class="np-order-hub-vat-mode' . ($vat_mode === 'inc' ? ' is-active' : '') . '" href="' . esc_url($vat_mode_urls['inc']) . '">Inkl mva</a>';
    echo '</div>';
    echo '</div>';
    echo '<div class="np-order-hub-revenue-toolbar">';
    echo '<div class="np-order-hub-revenue-controls">' . implode('', $period_links) . '</div>';
    if ($yearly_link !== '') {
        echo $yearly_link;
    }
    echo '<form class="np-order-hub-custom-range" method="get" action="' . esc_url($base_url) . '">';
    echo '<input type="hidden" name="np_period" value="custom" />';
    echo '<input type="hidden" name="np_vat_mode" value="' . esc_attr($vat_mode) . '" />';
    echo '<span class="np-order-hub-custom-label">Velg periode</span>';
    echo '<div class="np-order-hub-custom-fields">';
    echo '<input type="date" name="np_from" placeholder="29.01.26" value="' . esc_attr($custom_from_value) . '" />';
    echo '<span>til</span>';
    echo '<input type="date" name="np_to" placeholder="29.01.26" value="' . esc_attr($custom_to_value) . '" />';
    echo '<button type="submit">Vis</button>';
    echo '</div>';
    echo '</form>';
    echo '</div>';
    // Period meta hidden on request.

    $vat_rate = np_order_hub_get_vat_rate();
    $totals_split = np_order_hub_split_amount_with_vat((float) $totals['total'], $vat_rate);
    $total_ex_display = np_order_hub_format_money((float) $totals_split['net'], $currency_label);
    $total_inc_display = np_order_hub_format_money((float) $totals_split['gross'], $currency_label);
    $selected_mode_label = $is_inc_mode ? 'Inkl mva' : 'Eks mva';
    $selected_total_value = $is_inc_mode ? (float) $totals_split['gross'] : (float) $totals_split['net'];
    $selected_total_display = $is_inc_mode ? $total_inc_display : $total_ex_display;
    $total_orders = isset($totals['count']) ? (int) $totals['count'] : 0;
    $total_items = isset($item_counts['total_items']) ? (int) $item_counts['total_items'] : 0;
    $avg_order_value = $total_orders > 0 ? ($selected_total_value / $total_orders) : 0.0;
    $avg_order_display = np_order_hub_format_money($avg_order_value, $currency_label);
    $avg_items_value = $total_orders > 0 ? ($total_items / $total_orders) : 0.0;
    $avg_items_display = number_format($avg_items_value, 0, ',', ' ');
    echo '<div class="np-order-hub-revenue-metrics">';
    echo '<div class="np-order-hub-metric np-order-hub-metric-primary"><div class="np-order-hub-metric-label">Omsetning</div><div class="np-order-hub-metric-value">' . esc_html($selected_total_display) . '</div><div class="np-order-hub-metric-mode">' . esc_html($selected_mode_label) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Ordre</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_orders) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Plagg</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_items) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt ordre</div><div class="np-order-hub-metric-value">' . esc_html($avg_order_display) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt plagg</div><div class="np-order-hub-metric-value">' . esc_html($avg_items_display) . '</div></div>';
    echo '</div>';
    echo '<button type="button" class="np-order-hub-metrics-toggle" aria-expanded="false"><span>Se mer</span></button>';
    if ($has_multiple_currencies) {
        echo '<p class="np-order-hub-multi-currency">Flere valutaer i resultatet.</p>';
    }

    echo '<table class="np-order-hub-revenue-table">';
    echo '<thead><tr><th>Butikk</th><th>Omsetning</th><th>Ordre</th><th>Plagg</th><th>Snitt ordre</th><th>Snitt plagg</th></tr></thead>';
    echo '<tbody>';
    if (empty($rows)) {
        echo '<tr><td colspan="6">Ingen ordre funnet.</td></tr>';
    } else {
        foreach ($rows as $row) {
            $store_name = isset($row['store_name']) ? (string) $row['store_name'] : '';
            $store_key = isset($row['store_key']) ? sanitize_key((string) $row['store_key']) : '';
            $row_count = isset($row['count']) ? (int) $row['count'] : 0;
            $row_total = isset($row['total']) ? (float) $row['total'] : 0.0;
            $row_currency = isset($row['currency']) ? (string) $row['currency'] : '';
            $row_items = $store_key !== '' && isset($items_by_store[$store_key]) ? (int) $items_by_store[$store_key] : 0;
            $row_split = np_order_hub_split_amount_with_vat($row_total, $vat_rate);
            $row_selected_value = $is_inc_mode ? (float) $row_split['gross'] : (float) $row_split['net'];
            $row_revenue_display = np_order_hub_format_money($row_selected_value, $row_currency);
            $avg_value = $row_count > 0 ? ($row_selected_value / $row_count) : 0.0;
            $avg_display = np_order_hub_format_money($avg_value, $row_currency);
            $avg_items = $row_count > 0 ? ($row_items / $row_count) : 0.0;
            $avg_items_display = number_format($avg_items, 0, ',', ' ');
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
            echo '<td>' . esc_html($row_revenue_display) . '</td>';
            echo '<td>' . esc_html((string) $row_count) . '</td>';
            echo '<td>' . esc_html((string) $row_items) . '</td>';
            echo '<td>' . esc_html($avg_display) . '</td>';
            echo '<td>' . esc_html($avg_items_display) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody>';
    echo '</table>';
    echo '</div>';

    echo '<style>
        .np-order-hub-revenue-dashboard{width:85vw;max-width:85vw;margin:24px auto;font-family:inherit;box-sizing:border-box;margin-left:calc(50% - 42.5vw);margin-right:calc(50% - 42.5vw);font-size:16px;}
        .np-order-hub-revenue-dashboard *{font-size:16px;}
        .np-order-hub-revenue-toolbar{display:flex;flex-wrap:nowrap;gap:12px;align-items:center;margin:8px 0 6px;overflow-x:auto;}
        .np-order-hub-revenue-controls{display:flex;gap:8px;flex-wrap:nowrap;margin:0;white-space:nowrap;order:1;}
        .np-order-hub-vat-toggle-row{display:flex;justify-content:flex-end;margin:0 0 12px;}
        .np-order-hub-vat-toggle{display:flex;gap:4px;flex-wrap:nowrap;padding:4px;border:1px solid #d0d6e1;border-radius:10px;background:#fff;font-size:13px;}
        .np-order-hub-vat-mode{padding:6px 12px;border-radius:7px;text-decoration:none;color:#1f2937;line-height:1.2;font-size:13px;}
        .np-order-hub-vat-mode.is-active{background:#111827;color:#fff;}
        .np-order-hub-period{padding:8px 14px;border:1px solid #d0d6e1;border-radius:8px;text-decoration:none;color:#1f2937;background:#fff;}
        .np-order-hub-period.is-active{background:#111827;color:#fff;border-color:#111827;}
        .np-order-hub-period-yearly{order:2;white-space:nowrap;}
        .np-order-hub-period-meta{color:#6b7280;margin:0 0 16px;}
        .np-order-hub-custom-range{order:3;margin:0 0 0 auto;display:flex;align-items:center;gap:8px;flex-wrap:nowrap;white-space:nowrap;justify-content:flex-end;text-align:right;}
        .np-order-hub-custom-label{font-weight:600;color:#1f2937;}
        .np-order-hub-custom-fields{display:flex;flex-wrap:nowrap;gap:8px;align-items:center;}
        .np-order-hub-custom-fields input[type="date"]{padding:6px 8px;border:1px solid #d0d6e1;border-radius:6px;}
        .np-order-hub-custom-fields button{padding:6px 12px;border-radius:6px;border:1px solid #111827;background:#111827;color:#fff;cursor:pointer;}
        .np-order-hub-revenue-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:30px 0;width:100%;}
        .np-order-hub-metric{display:flex;flex-direction:column;gap:4px;align-items:flex-start;background:#f8f9fc;border:1px solid #e5e7eb;border-radius:12px;padding:16px 20px;}
        .np-order-hub-metric-value{font-size:20px;font-weight:700;}
        .np-order-hub-metric-label{color:#6b7280;}
        .np-order-hub-metric-mode{font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:0.02em;}
        .np-order-hub-metrics-toggle{display:none;align-items:center;justify-content:space-between;gap:8px;width:100%;padding:12px 16px;border-radius:12px;border:1px solid #e5e7eb;background:#fff;color:#111827;font-weight:600;cursor:pointer;}
        .np-order-hub-metrics-toggle::after{content:"↓";font-size:16px;line-height:1;}
        .np-order-hub-metrics-toggle[aria-expanded="true"]::after{content:"↑";}
        .np-order-hub-multi-currency{color:#b45309;margin:0 0 12px;}
        .np-order-hub-revenue-table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;}
        .np-order-hub-revenue-table th,
        .np-order-hub-revenue-table td{padding:12px 14px;border-bottom:1px solid #eef2f7;text-align:left;}
        .np-order-hub-revenue-table th{background:#f8fafc;font-weight:600;}
        .np-order-hub-revenue-table tbody tr:last-child td{border-bottom:none;}
        .np-order-hub-debug-box{white-space:pre-wrap;background:#111827;color:#e5e7eb;padding:12px;border-radius:8px;font-size:16px;}
        body.np-order-hub-dashboard-page .wp-site-blocks > header,
        body.np-order-hub-dashboard-page .wp-site-blocks > footer{display:none !important;}
        body.np-order-hub-dashboard-page .wp-block-group.alignfull.has-global-padding.is-layout-constrained.wp-block-group-is-layout-constrained{padding-top:0 !important;}
        body.np-order-hub-dashboard-page .wp-block-post-title,
        body.np-order-hub-dashboard-page .entry-content .wp-block-site-title,
        body.np-order-hub-dashboard-page .entry-content .wp-block-navigation,
        body.np-order-hub-dashboard-page .entry-content .wp-block-page-list,
        body.np-order-hub-dashboard-page .entry-content p.has-small-font-size,
        body.np-order-hub-dashboard-page .wp-block-post-content .wp-block-site-title,
        body.np-order-hub-dashboard-page .wp-block-post-content .wp-block-navigation,
        body.np-order-hub-dashboard-page .wp-block-post-content .wp-block-page-list,
        body.np-order-hub-dashboard-page .wp-block-post-content p.has-small-font-size{display:none !important;}
        body.np-order-hub-dashboard-page .entry-content > .wp-block-spacer,
        body.np-order-hub-dashboard-page .wp-block-post-content > .wp-block-spacer{display:none !important;}
        @media (max-width:768px){
            .np-order-hub-revenue-dashboard{font-size:16px;width:100%;max-width:100%;margin:0 auto;box-sizing:border-box;padding:0;}
            .np-order-hub-revenue-dashboard *{font-size:16px;}
            .np-order-hub-revenue-toolbar{display:grid;grid-template-columns:auto 1fr;align-items:start;gap:8px 10px;overflow-x:visible;}
            .np-order-hub-period-yearly{order:0;grid-column:1;}
            .np-order-hub-revenue-controls{order:1;grid-column:1 / -1;flex-wrap:wrap;width:100%;}
            .np-order-hub-custom-range{order:0;grid-column:2;justify-self:stretch;width:100%;}
            .np-order-hub-vat-toggle-row{justify-content:flex-start;margin:0 0 10px;}
            .np-order-hub-vat-toggle{width:fit-content;}
            .np-order-hub-vat-mode{font-size:13px;}
            .np-order-hub-custom-label{display:none;}
            .np-order-hub-custom-fields{width:100%;display:grid;grid-template-columns:1fr auto 1fr auto;gap:6px;align-items:center;}
            .np-order-hub-custom-fields input[type="date"]{width:100%;min-width:0;}
            .np-order-hub-custom-fields button{padding:6px 10px;}
            .np-order-hub-revenue-metrics{grid-template-columns:1fr;}
            .np-order-hub-metric{width:100%;flex-direction:row;align-items:center;justify-content:space-between;}
            .np-order-hub-metric-value{font-size:20px;}
            .np-order-hub-metric-label{font-size:16px;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric{display:none;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric-primary{display:flex;}
            .np-order-hub-metrics-toggle{display:flex;}
            .np-order-hub-revenue-table{display:block;overflow-x:auto;width:100%;}
            .np-order-hub-revenue-total{width:100%;}
        }
    </style>';
    if ($refresh_seconds > 0) {
        echo '<script>
            (function(){
                var refreshMs = ' . (int) $refresh_seconds . ' * 1000;
                if (refreshMs > 0) {
                    setTimeout(function(){ window.location.reload(); }, refreshMs);
                }
            })();
        </script>';
    }
    echo '<script>
        (function(){
            var roots = document.querySelectorAll(".np-order-hub-revenue-dashboard");
            if (!roots.length) { return; }
            document.body.classList.add("np-order-hub-dashboard-page");
            var cleanupSelectors = [
                ".wp-block-post-title",
                ".wp-block-site-title",
                ".wp-block-navigation",
                ".wp-block-page-list",
                "p.has-small-font-size",
                ".wp-block-spacer"
            ];
            roots.forEach(function(root){
                var contentRoot = root.closest(".entry-content, .wp-block-post-content");
                if (contentRoot) {
                    cleanupSelectors.forEach(function(selector){
                        var nodes = contentRoot.querySelectorAll(selector);
                        nodes.forEach(function(node){
                            if (!root.contains(node)) {
                                node.style.display = "none";
                            }
                        });
                    });
                }
                var metrics = root.querySelector(".np-order-hub-revenue-metrics");
                var toggle = root.querySelector(".np-order-hub-metrics-toggle");
                if (!metrics || !toggle) { return; }
                var label = toggle.querySelector("span");
                var setState = function(expanded){
                    metrics.classList.toggle("is-expanded", expanded);
                    toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
                    if (label) {
                        label.textContent = expanded ? "Se mindre" : "Se mer";
                    }
                };
                setState(false);
                toggle.addEventListener("click", function(){
                    setState(!metrics.classList.contains("is-expanded"));
                });
            });
        })();
    </script>';

    return ob_get_clean();
}