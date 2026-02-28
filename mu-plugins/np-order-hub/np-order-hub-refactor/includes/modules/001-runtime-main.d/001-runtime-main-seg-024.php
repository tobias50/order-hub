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
    echo '<label><input type="checkbox" name="np_order_hub_pushover_enabled" value="1"' . checked($settings['enabled'], true, false) . ' /> Send notifications for new orders and print-agent alerts</label>';
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
            $total_a = isset($a['total']) ? (float) $a['total'] : 0.0;
            $total_b = isset($b['total']) ? (float) $b['total'] : 0.0;
            if ($total_a !== $total_b) {
                return ($total_a < $total_b) ? 1 : -1;
            }
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
    $period_links_primary = array();
    $period_links_extra = array();
    $extra_period_keys = array('month_current', 'month_previous', 'yearly');
    foreach ($period_urls as $key => $url) {
        $active = $range['period'] === $key ? ' is-active' : '';
        $label = isset($period_labels[$key]) ? $period_labels[$key] : $key;
        $is_extra_period = in_array($key, $extra_period_keys, true);
        $period_class = $is_extra_period ? ' np-order-hub-period-extra' : ' np-order-hub-period-primary';
        $link_html = '<a class="np-order-hub-period' . $period_class . $active . '" data-period="' . esc_attr($key) . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
        if ($is_extra_period) {
            $period_links_extra[] = $link_html;
        } else {
            $period_links_primary[] = $link_html;
        }
    }
    $has_active_extra_period = in_array($range['period'], $extra_period_keys, true);

    echo '<div class="np-order-hub-vat-toggle-row">';
    echo '<div class="np-order-hub-vat-toggle">';
    echo '<a class="np-order-hub-vat-mode' . ($vat_mode === 'ex' ? ' is-active' : '') . '" href="' . esc_url($vat_mode_urls['ex']) . '">Eks mva</a>';
    echo '<a class="np-order-hub-vat-mode' . ($vat_mode === 'inc' ? ' is-active' : '') . '" href="' . esc_url($vat_mode_urls['inc']) . '">Inkl mva</a>';
    echo '</div>';
    echo '<form class="np-order-hub-custom-range" method="get" action="' . esc_url($base_url) . '">';
    echo '<input type="hidden" name="np_period" value="custom" />';
    echo '<input type="hidden" name="np_vat_mode" value="' . esc_attr($vat_mode) . '" />';
    echo '<input type="hidden" name="np_from" value="' . esc_attr($custom_from_value) . '" />';
    echo '<input type="hidden" name="np_to" value="' . esc_attr($custom_to_value) . '" />';
    echo '<button type="button" class="np-order-hub-date-dialog-toggle">Velg dato</button>';
    echo '</form>';
    echo '</div>';
    echo '<div class="np-order-hub-date-dialog" hidden>';
    echo '<div class="np-order-hub-date-dialog-backdrop"></div>';
    echo '<div class="np-order-hub-date-dialog-panel" role="dialog" aria-modal="true" aria-label="Velg dato">';
    echo '<h3>Velg dato</h3>';
    echo '<label>Fra<input class="np-order-hub-date-dialog-from" type="date" value="' . esc_attr($custom_from_value) . '" /></label>';
    echo '<label>Til<input class="np-order-hub-date-dialog-to" type="date" value="' . esc_attr($custom_to_value) . '" /></label>';
    echo '<div class="np-order-hub-date-dialog-actions">';
    echo '<button type="button" class="np-order-hub-date-dialog-cancel">Avbryt</button>';
    echo '<button type="button" class="np-order-hub-date-dialog-apply">Vis</button>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '<div class="np-order-hub-revenue-toolbar">';
    echo '<div class="np-order-hub-revenue-controls' . ($has_active_extra_period ? ' is-expanded' : '') . '">';
    echo implode('', $period_links_primary);
    if (!empty($period_links_extra)) {
        echo '<button type="button" class="np-order-hub-periods-toggle" aria-expanded="' . ($has_active_extra_period ? 'true' : 'false') . '"><span>' . ($has_active_extra_period ? 'Se mindre' : 'Se mer') . '</span></button>';
        echo '<div class="np-order-hub-periods-extra">' . implode('', $period_links_extra) . '</div>';
    }
    echo '</div>';
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
    $avg_items_decimals = abs($avg_items_value - round($avg_items_value)) < 0.00001 ? 0 : 1;
    $avg_items_display = number_format($avg_items_value, $avg_items_decimals, ',', ' ');
    echo '<div class="np-order-hub-revenue-metrics">';
    echo '<div class="np-order-hub-metric np-order-hub-metric-primary"><div class="np-order-hub-metric-value">' . esc_html($selected_total_display) . '</div><div class="np-order-hub-metric-mode">' . esc_html($selected_mode_label) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Ordre</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_orders) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Plagg</div><div class="np-order-hub-metric-value">' . esc_html((string) $total_items) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt ordre</div><div class="np-order-hub-metric-value">' . esc_html($avg_order_display) . '</div></div>';
    echo '<div class="np-order-hub-metric"><div class="np-order-hub-metric-label">Snitt plagg</div><div class="np-order-hub-metric-value">' . esc_html($avg_items_display) . '</div></div>';
    echo '</div>';
    echo '<button type="button" class="np-order-hub-metrics-toggle" aria-expanded="false"><span>Se mer</span></button>';
    if ($has_multiple_currencies) {
        echo '<p class="np-order-hub-multi-currency">Flere valutaer i resultatet.</p>';
    }

    echo '<div class="np-order-hub-revenue-table-wrap">';
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
            $avg_items_decimals = abs($avg_items - round($avg_items)) < 0.00001 ? 0 : 1;
            $avg_items_display = number_format($avg_items, $avg_items_decimals, ',', ' ');
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
    echo '</div>';

    echo '<style>
        .np-order-hub-revenue-dashboard{width:85vw;max-width:85vw;margin:24px auto;font-family:inherit;box-sizing:border-box;margin-left:calc(50% - 42.5vw);margin-right:calc(50% - 42.5vw);font-size:16px;}
        .np-order-hub-revenue-dashboard *{font-size:16px;}
        .np-order-hub-revenue-toolbar{display:flex;gap:12px;align-items:center;margin:8px 0 6px;overflow-x:auto;width:100%;max-width:100%;}
        .np-order-hub-revenue-controls{display:flex;gap:8px;flex-wrap:nowrap;margin:0;white-space:nowrap;align-items:center;width:100%;}
        .np-order-hub-periods-extra{display:flex;gap:8px;flex-wrap:nowrap;align-items:center;}
        .np-order-hub-periods-toggle{display:none;align-items:center;justify-content:center;gap:6px;padding:8px 14px;border:1px solid #d0d6e1;border-radius:8px;background:#fff;color:#1f2937;cursor:pointer;white-space:nowrap;}
        .np-order-hub-vat-toggle-row{display:flex;justify-content:space-between;align-items:center;gap:8px;margin:0 0 12px;flex-wrap:nowrap;width:100%;max-width:100%;}
        .np-order-hub-vat-toggle{display:flex;gap:4px;flex-wrap:nowrap;padding:4px;border:1px solid #d0d6e1;border-radius:10px;background:#fff;font-size:13px;}
        .np-order-hub-vat-mode{padding:6px 12px;border-radius:7px;text-decoration:none;color:#1f2937;line-height:1.2;font-size:13px;}
        .np-order-hub-vat-mode.is-active{background:#111827;color:#fff;}
        .np-order-hub-period{padding:8px 14px;border:1px solid #d0d6e1;border-radius:8px;text-decoration:none;color:#1f2937;background:#fff;}
        .np-order-hub-period.is-active{background:#111827;color:#fff;border-color:#111827;}
        .np-order-hub-period-meta{color:#6b7280;margin:0 0 16px;}
        .np-order-hub-custom-range{margin:0;display:flex;align-items:center;flex:0 0 auto;}
        .np-order-hub-date-dialog-toggle{padding:8px 14px;border-radius:8px;border:1px solid #d0d6e1;background:#fff;color:#1f2937;cursor:pointer;line-height:1.2;white-space:nowrap;}
        .np-order-hub-date-dialog[hidden]{display:none !important;}
        .np-order-hub-date-dialog{position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;padding:16px;}
        .np-order-hub-date-dialog-backdrop{position:absolute;inset:0;background:rgba(17,24,39,0.45);}
        .np-order-hub-date-dialog-panel{position:relative;z-index:1;width:min(360px,100%);background:#fff;border-radius:12px;padding:14px;border:1px solid #d0d6e1;display:flex;flex-direction:column;gap:10px;}
        .np-order-hub-date-dialog-panel h3{margin:0;font-size:16px;}
        .np-order-hub-date-dialog-panel label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:#374151;}
        .np-order-hub-date-dialog-panel input[type="date"]{padding:8px;border:1px solid #d0d6e1;border-radius:8px;}
        .np-order-hub-date-dialog-actions{display:flex;justify-content:flex-end;gap:8px;}
        .np-order-hub-date-dialog-cancel,
        .np-order-hub-date-dialog-apply{padding:7px 11px;border-radius:8px;border:1px solid #d0d6e1;background:#fff;color:#111827;cursor:pointer;font-size:13px;}
        .np-order-hub-date-dialog-apply{border-color:#111827;background:#111827;color:#fff;}
        .np-order-hub-revenue-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:30px 0;width:100%;box-sizing:border-box;}
        .np-order-hub-metric{display:flex;flex-direction:column;gap:4px;align-items:flex-start;background:#f8f9fc;border:1px solid #e5e7eb;border-radius:12px;padding:16px 20px;box-sizing:border-box;}
        .np-order-hub-metric-primary{border:1px solid #cfd6e2;}
        .np-order-hub-metric-value{font-size:20px;font-weight:700;}
        .np-order-hub-metric-label{color:#6b7280;}
        .np-order-hub-metric-mode{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:0.02em;}
        .np-order-hub-metrics-toggle{display:none;align-items:center;justify-content:space-between;gap:8px;width:100%;padding:12px 16px;border-radius:12px;border:1px solid #e5e7eb;background:#fff;color:#111827;font-weight:600;cursor:pointer;}
        .np-order-hub-metrics-toggle::after{content:"↓";font-size:16px;line-height:1;}
        .np-order-hub-metrics-toggle[aria-expanded="true"]::after{content:"↑";}
        .np-order-hub-multi-currency{color:#b45309;margin:0 0 12px;}
        .np-order-hub-revenue-table-wrap{width:100%;max-width:100%;overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch;border:1px solid #e5e7eb;border-radius:12px;background:#fff;}
        .np-order-hub-revenue-table{width:100%;min-width:840px;table-layout:fixed;border-collapse:collapse;background:#fff;}
        .np-order-hub-revenue-table th,
        .np-order-hub-revenue-table td{padding:12px 14px;border-bottom:1px solid #eef2f7;text-align:left;white-space:nowrap;}
        .np-order-hub-revenue-table th:nth-child(1),
        .np-order-hub-revenue-table td:nth-child(1){width:45%;}
        .np-order-hub-revenue-table th:nth-child(2),
        .np-order-hub-revenue-table td:nth-child(2){width:25%;}
        .np-order-hub-revenue-table th{background:#f8fafc;font-weight:600;}
        .np-order-hub-revenue-table tbody tr:last-child td{border-bottom:none;}
        .np-order-hub-debug-box{white-space:pre-wrap;background:#111827;color:#e5e7eb;padding:12px;border-radius:8px;font-size:16px;}
        body.np-order-hub-dashboard-page .wp-site-blocks > header,
        body.np-order-hub-dashboard-page .wp-site-blocks > footer{display:none !important;}
        body.np-order-hub-dashboard-page main.wp-block-group.has-global-padding.is-layout-constrained.wp-block-group-is-layout-constrained{
            margin-top:calc(var(--wp--preset--spacing--60, 21px) - 40px) !important;
        }
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
        body.np-order-hub-dashboard-page .entry-content,
        body.np-order-hub-dashboard-page .wp-block-post-content,
        body.np-order-hub-dashboard-page .wp-block-group.alignfull.has-global-padding.is-layout-constrained.wp-block-group-is-layout-constrained{
            width:100% !important;
            max-width:100% !important;
            margin-left:0 !important;
            margin-right:0 !important;
            padding-left:0 !important;
            padding-right:0 !important;
        }
        body.np-order-hub-dashboard-page,
        body.np-order-hub-dashboard-page .wp-site-blocks,
        body.np-order-hub-dashboard-page .wp-block-post-content{overflow-x:hidden;}
        body.np-order-hub-date-dialog-open{overflow:hidden;}
        @media (min-width:769px){
            .np-order-hub-revenue-toolbar{display:flex;align-items:center;gap:12px;overflow-x:visible;}
            .np-order-hub-revenue-controls{flex:1 1 auto;width:auto;min-width:0;}
            .np-order-hub-revenue-toolbar > .np-order-hub-vat-toggle{margin-left:auto;flex:0 0 auto;}
            .np-order-hub-revenue-table-wrap{overflow-x:visible;overflow-y:visible;-webkit-overflow-scrolling:auto;}
            .np-order-hub-revenue-table{min-width:0;}
            .np-order-hub-revenue-table th:nth-child(1),
            .np-order-hub-revenue-table td:nth-child(1){width:42%;}
            .np-order-hub-revenue-table th:nth-child(n+2),
            .np-order-hub-revenue-table td:nth-child(n+2){width:11.6%;text-align:center;}
        }
        @media (max-width:768px){
            .np-order-hub-revenue-dashboard{font-size:16px;width:100%;max-width:100%;margin:0;box-sizing:border-box;padding:0 5px 0 0;}
            .np-order-hub-revenue-dashboard *{font-size:13px;}
            .np-order-hub-revenue-toolbar{display:block;overflow-x:visible;width:100%;max-width:100%;}
            .np-order-hub-revenue-controls{width:100%;min-width:0;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;align-items:stretch;}
            .np-order-hub-period,
            .np-order-hub-periods-toggle,
            .np-order-hub-date-dialog-toggle{display:flex;align-items:center;justify-content:center;padding:6px 8px;border-radius:8px;font-size:13px;line-height:1.2;white-space:nowrap;}
            .np-order-hub-period-primary{order:initial;}
            .np-order-hub-custom-range{margin:0;width:100%;order:initial;}
            .np-order-hub-custom-range .np-order-hub-date-dialog-toggle{width:100%;}
            .np-order-hub-periods-toggle{display:flex;order:initial;margin-left:0;width:100%;}
            .np-order-hub-periods-extra{display:none;grid-column:1 / -1;width:100%;gap:6px;flex-wrap:wrap;}
            .np-order-hub-revenue-controls.is-expanded .np-order-hub-periods-extra{display:flex;}
            .np-order-hub-vat-toggle-row{justify-content:flex-end;align-items:center;gap:6px;margin:0 0 10px;flex-wrap:nowrap;width:100%;max-width:100%;overflow:visible;}
            .np-order-hub-vat-toggle{width:auto;flex:0 0 auto;gap:2px;padding:2px;border-radius:8px;margin-top:0px;margin-left:auto;}
            .np-order-hub-vat-mode{font-size:11px;padding:5px 8px;}
            .np-order-hub-date-dialog{padding:12px;}
            .np-order-hub-date-dialog-panel{width:min(330px,100%);}
            .np-order-hub-revenue-metrics{grid-template-columns:1fr;border:1px solid #cfd6e2;border-radius:12px;padding:0;overflow:hidden;margin:15px 0 9px 0;}
            .np-order-hub-metric{width:100%;flex-direction:column;align-items:flex-start;justify-content:flex-start;}
            .np-order-hub-metric-value{font-size:20px;}
            .np-order-hub-metric-label{font-size:16px;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric{display:none;}
            .np-order-hub-revenue-metrics:not(.is-expanded) .np-order-hub-metric-primary{display:flex;}
            .np-order-hub-metrics-toggle{display:flex;margin-bottom:20px;}
            .np-order-hub-revenue-table-wrap{width:100%;max-width:100%;overflow-x:auto;overflow-y:hidden;box-sizing:border-box;}
            .np-order-hub-revenue-table{min-width:680px;}
            .np-order-hub-revenue-table th,
            .np-order-hub-revenue-table td{padding:10px 10px;}
            .np-order-hub-revenue-table th:nth-child(1),
            .np-order-hub-revenue-table td:nth-child(1){width:32%;}
            .np-order-hub-revenue-table th:nth-child(2),
            .np-order-hub-revenue-table td:nth-child(2){width:24%;text-align:right;padding-right:32px;}
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
                var periodControls = root.querySelector(".np-order-hub-revenue-controls");
                var periodToggle = root.querySelector(".np-order-hub-periods-toggle");
                var dateForm = root.querySelector(".np-order-hub-custom-range");
                var vatRow = root.querySelector(".np-order-hub-vat-toggle-row");
                var vatToggle = root.querySelector(".np-order-hub-vat-toggle");
                var toolbar = root.querySelector(".np-order-hub-revenue-toolbar");
                var isMobile = window.matchMedia("(max-width:768px)").matches;
                if (vatToggle) {
                    if (isMobile && vatRow) {
                        vatRow.insertBefore(vatToggle, vatRow.firstChild);
                        vatRow.style.display = "flex";
                    } else if (!isMobile && toolbar) {
                        toolbar.appendChild(vatToggle);
                        if (vatRow) {
                            vatRow.style.display = "none";
                        }
                    }
                }
                if (periodControls && periodToggle && dateForm && isMobile) {
                    periodControls.insertBefore(dateForm, periodToggle);
                } else if (dateForm && !isMobile) {
                    var yearlyLink = periodControls ? periodControls.querySelector(".np-order-hub-period-extra[data-period=\"yearly\"]") : null;
                    if (yearlyLink && yearlyLink.parentNode) {
                        yearlyLink.parentNode.insertBefore(dateForm, yearlyLink.nextSibling);
                    } else if (periodControls) {
                        periodControls.appendChild(dateForm);
                    } else if (vatRow) {
                        vatRow.appendChild(dateForm);
                    }
                }
                if (periodControls && periodToggle) {
                    var periodLabel = periodToggle.querySelector("span");
                    var hasActiveExtra = !!periodControls.querySelector(".np-order-hub-periods-extra .np-order-hub-period.is-active");
                    var setPeriodState = function(expanded){
                        periodControls.classList.toggle("is-expanded", expanded);
                        periodToggle.setAttribute("aria-expanded", expanded ? "true" : "false");
                        if (periodLabel) {
                            periodLabel.textContent = expanded ? "Se mindre" : "Se mer";
                        }
                    };
                    setPeriodState(hasActiveExtra);
                    periodToggle.addEventListener("click", function(){
                        setPeriodState(!periodControls.classList.contains("is-expanded"));
                    });
                }

                var dateToggle = root.querySelector(".np-order-hub-date-dialog-toggle");
                var dateDialog = root.querySelector(".np-order-hub-date-dialog");
                if (dateForm && dateToggle && dateDialog) {
                    var fromHidden = dateForm.querySelector("input[name=\'np_from\']");
                    var toHidden = dateForm.querySelector("input[name=\'np_to\']");
                    var fromPicker = dateDialog.querySelector(".np-order-hub-date-dialog-from");
                    var toPicker = dateDialog.querySelector(".np-order-hub-date-dialog-to");
                    var cancelButton = dateDialog.querySelector(".np-order-hub-date-dialog-cancel");
                    var applyButton = dateDialog.querySelector(".np-order-hub-date-dialog-apply");
                    var backdrop = dateDialog.querySelector(".np-order-hub-date-dialog-backdrop");

                    var closeDateDialog = function(){
                        dateDialog.setAttribute("hidden", "hidden");
                        document.body.classList.remove("np-order-hub-date-dialog-open");
                    };
                    var openDateDialog = function(){
                        if (fromPicker && fromHidden) {
                            fromPicker.value = fromHidden.value || "";
                        }
                        if (toPicker && toHidden) {
                            toPicker.value = toHidden.value || "";
                        }
                        dateDialog.removeAttribute("hidden");
                        document.body.classList.add("np-order-hub-date-dialog-open");
                    };

                    dateToggle.addEventListener("click", function(event){
                        event.preventDefault();
                        openDateDialog();
                    });
                    if (cancelButton) {
                        cancelButton.addEventListener("click", function(event){
                            event.preventDefault();
                            closeDateDialog();
                        });
                    }
                    if (backdrop) {
                        backdrop.addEventListener("click", closeDateDialog);
                    }
                    if (applyButton) {
                        applyButton.addEventListener("click", function(event){
                            event.preventDefault();
                            if (fromHidden && fromPicker) {
                                fromHidden.value = fromPicker.value || "";
                            }
                            if (toHidden && toPicker) {
                                toHidden.value = toPicker.value || "";
                            }
                            closeDateDialog();
                            dateForm.submit();
                        });
                    }
                    dateDialog.addEventListener("keydown", function(event){
                        if (event.key === "Escape") {
                            closeDateDialog();
                        }
                    });
                }

                var metrics = root.querySelector(".np-order-hub-revenue-metrics");
                var toggle = root.querySelector(".np-order-hub-metrics-toggle");
                if (metrics && toggle) {
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
                }
            });
        })();
    </script>';

    return ob_get_clean();
}
