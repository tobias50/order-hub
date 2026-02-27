<?php
function np_order_hub_send_packing_slips_preview_page($links, $merge_error = '') {
    if (empty($links) || !is_array($links)) {
        return;
    }
    while (ob_get_level()) {
        @ob_end_clean();
    }
    nocache_headers();
    header('Content-Type: text/html; charset=' . get_bloginfo('charset'));
    echo '<!doctype html><html><head><meta charset="' . esc_attr(get_bloginfo('charset')) . '">';
    echo '<title>Packing slips preview</title>';
    echo '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;}';
    echo 'h1{margin:0 0 12px;font-size:20px;}';
    echo 'p{margin:0 0 12px;color:#444;}';
    echo 'ul{padding-left:18px;}';
    echo 'li{margin:8px 0;}';
    echo '.btn{display:inline-block;margin:12px 0;padding:8px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px;}';
    echo '</style></head><body>';
    echo '<h1>Packing slips</h1>';
    echo '<p>Kunne ikke slå sammen PDF-ene til ett dokument. Åpne hver butikk i forhåndsvisning:</p>';
    if (is_string($merge_error) && $merge_error !== '') {
        echo '<p style="color:#b32d2e; margin-top:6px;">Feil: ' . esc_html($merge_error) . '</p>';
    }
    echo '<a class="btn" href="#" id="np-open-all">Åpne alle</a>';
    echo '<ul>';
    $urls = array();
    foreach ($links as $link) {
        $label = isset($link['label']) ? (string) $link['label'] : 'Store';
        $count = isset($link['count']) ? (int) $link['count'] : 0;
        $url = isset($link['url']) ? (string) $link['url'] : '';
        if ($url === '') {
            continue;
        }
        $urls[] = $url;
        $label_text = $label;
        if ($count > 0) {
            $label_text .= ' (' . $count . ')';
        }
        echo '<li><a href="' . esc_url($url) . '" target="_blank" rel="noopener noreferrer">' . esc_html($label_text) . '</a></li>';
    }
    echo '</ul>';
    echo '<script>(function(){var links=' . wp_json_encode($urls) . ';';
    echo 'var btn=document.getElementById("np-open-all");';
    echo 'if(btn){btn.addEventListener("click",function(e){e.preventDefault();';
    echo 'links.forEach(function(url){window.open(url,"_blank");});';
    echo '});}})();</script>';
    echo '</body></html>';
    exit;
}

function np_order_hub_print_queue_get_jobs() {
    $jobs = get_option(NP_ORDER_HUB_PRINT_QUEUE_OPTION, array());
    return is_array($jobs) ? $jobs : array();
}

function np_order_hub_print_queue_save_jobs($jobs) {
    if (!is_array($jobs)) {
        $jobs = array();
    }
    uasort($jobs, function ($a, $b) {
        $a_time = isset($a['updated_at_gmt']) ? strtotime((string) $a['updated_at_gmt']) : 0;
        $b_time = isset($b['updated_at_gmt']) ? strtotime((string) $b['updated_at_gmt']) : 0;
        if ($a_time === $b_time) {
            return 0;
        }
        return $a_time > $b_time ? -1 : 1;
    });
    $jobs = array_slice($jobs, 0, 500, true);
    update_option(NP_ORDER_HUB_PRINT_QUEUE_OPTION, $jobs, false);
}

function np_order_hub_print_queue_job_key($store_key, $order_id) {
    $store_key = sanitize_key((string) $store_key);
    $order_id = absint($order_id);
    if ($store_key === '' || $order_id < 1) {
        return '';
    }
    return $store_key . ':' . $order_id;
}

function np_order_hub_get_print_agent_token($generate_if_missing = true) {
    $token = trim((string) get_option(NP_ORDER_HUB_PRINT_AGENT_TOKEN_OPTION, ''));
    if ($token === '' && $generate_if_missing) {
        $token = wp_generate_password(48, false, false);
        update_option(NP_ORDER_HUB_PRINT_AGENT_TOKEN_OPTION, $token, false);
    }
    return $token;
}

function np_order_hub_regenerate_print_agent_token() {
    $token = wp_generate_password(48, false, false);
    update_option(NP_ORDER_HUB_PRINT_AGENT_TOKEN_OPTION, $token, false);
    return $token;
}

function np_order_hub_print_agent_token_from_request(WP_REST_Request $request) {
    $token = trim((string) $request->get_header('X-NP-Print-Token'));
    if ($token === '') {
        $token = trim((string) $request->get_param('token'));
    }
    return $token;
}

function np_order_hub_print_agent_is_authorized(WP_REST_Request $request) {
    $expected = np_order_hub_get_print_agent_token(true);
    $provided = np_order_hub_print_agent_token_from_request($request);
    if ($expected === '' || $provided === '') {
        return false;
    }
    return hash_equals($expected, $provided);
}

function np_order_hub_print_agent_update_heartbeat($agent_name = '', $event = 'claim', $meta = array()) {
    $state = get_option(NP_ORDER_HUB_PRINT_AGENT_HEARTBEAT_OPTION, array());
    if (!is_array($state)) {
        $state = array();
    }

    $state['last_seen_gmt'] = gmdate('Y-m-d H:i:s');
    $state['last_event'] = sanitize_key((string) $event);

    $agent_name = sanitize_text_field((string) $agent_name);
    if ($agent_name !== '') {
        $state['agent_name'] = $agent_name;
    }

    if (is_array($meta) && !empty($meta)) {
        if (isset($meta['status'])) {
            $state['status'] = sanitize_key((string) $meta['status']);
        }
        if (isset($meta['job_key'])) {
            $state['job_key'] = sanitize_text_field((string) $meta['job_key']);
        }
    }

    update_option(NP_ORDER_HUB_PRINT_AGENT_HEARTBEAT_OPTION, $state, false);
}

function np_order_hub_print_agent_get_heartbeat() {
    $state = get_option(NP_ORDER_HUB_PRINT_AGENT_HEARTBEAT_OPTION, array());
    return is_array($state) ? $state : array();
}

function np_order_hub_print_queue_append_log(&$job, $message) {
    $message = trim((string) $message);
    if ($message === '') {
        return;
    }
    if (empty($job['log']) || !is_array($job['log'])) {
        $job['log'] = array();
    }
    $job['log'][] = gmdate('Y-m-d H:i:s') . ' ' . $message;
    if (count($job['log']) > 20) {
        $job['log'] = array_slice($job['log'], -20);
    }
}

function np_order_hub_print_queue_get_job($job_key) {
    $jobs = np_order_hub_print_queue_get_jobs();
    return isset($jobs[$job_key]) && is_array($jobs[$job_key]) ? $jobs[$job_key] : null;
}

function np_order_hub_print_queue_set_job($job_key, $job) {
    if (!is_array($job)) {
        return;
    }
    $jobs = np_order_hub_print_queue_get_jobs();
    $jobs[$job_key] = $job;
    np_order_hub_print_queue_save_jobs($jobs);
}

function np_order_hub_print_queue_remove_job($job_key) {
    $jobs = np_order_hub_print_queue_get_jobs();
    if (isset($jobs[$job_key])) {
        $job = is_array($jobs[$job_key]) ? $jobs[$job_key] : array();
        if (!empty($job['document_path']) && is_string($job['document_path']) && is_file($job['document_path'])) {
            @unlink($job['document_path']);
        }
        unset($jobs[$job_key]);
        np_order_hub_print_queue_save_jobs($jobs);
    }
    $next = wp_next_scheduled(NP_ORDER_HUB_PRINT_QUEUE_EVENT, array($job_key));
    if ($next) {
        wp_unschedule_event($next, NP_ORDER_HUB_PRINT_QUEUE_EVENT, array($job_key));
    }
}

function np_order_hub_print_queue_is_root_store($store) {
    if (!is_array($store) || empty($store['url'])) {
        return false;
    }
    $host = strtolower((string) wp_parse_url((string) $store['url'], PHP_URL_HOST));
    if ($host === '') {
        return false;
    }
    $host = trim($host, '.');
    if ($host === 'ordrehub.nordicprofil.no') {
        return false;
    }
    if ($host === 'root.nordicprofil.no') {
        return true;
    }
    $suffix = '.nordicprofil.no';
    if ($host === 'nordicprofil.no' || (strlen($host) > strlen($suffix) && substr($host, -strlen($suffix)) === $suffix)) {
        return true;
    }
    return strpos($host, '.root.') !== false;
}

function np_order_hub_print_queue_is_store_allowed($store) {
    $allowed = np_order_hub_print_queue_is_root_store($store);
    return (bool) apply_filters('np_order_hub_print_queue_store_allowed', $allowed, $store);
}

function np_order_hub_print_queue_extract_payload($record) {
    if (!is_array($record) || empty($record['payload'])) {
        return array();
    }
    $payload = json_decode((string) $record['payload'], true);
    return is_array($payload) ? $payload : array();
}

function np_order_hub_print_queue_get_order_record($store_key, $order_id) {
    global $wpdb;
    $table = np_order_hub_table_name();
    $row = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT * FROM $table WHERE store_key = %s AND order_id = %d LIMIT 1",
            sanitize_key((string) $store_key),
            absint($order_id)
        ),
        ARRAY_A
    );
    return is_array($row) ? $row : null;
}

function np_order_hub_print_queue_should_enqueue($store, $record, $payload = array()) {
    if (!is_array($store) || !is_array($record)) {
        return false;
    }
    if (!np_order_hub_print_queue_is_store_allowed($store)) {
        return false;
    }
    $status = isset($record['status']) ? sanitize_key((string) $record['status']) : '';
    if ($status !== 'processing') {
        return false;
    }
    $bucket = np_order_hub_extract_delivery_bucket_from_payload_data($payload);
    if ($bucket === '') {
        $bucket = np_order_hub_record_delivery_bucket($record);
    }
    return $bucket !== NP_ORDER_HUB_DELIVERY_BUCKET_SCHEDULED;
}

function np_order_hub_print_queue_schedule_event($job_key, $run_at_ts) {
    $run_at_ts = (int) $run_at_ts;
    if ($run_at_ts < (time() + 5)) {
        $run_at_ts = time() + 5;
    }
    $args = array($job_key);
    $existing = wp_next_scheduled(NP_ORDER_HUB_PRINT_QUEUE_EVENT, $args);
    if ($existing && $existing <= $run_at_ts) {
        return $existing;
    }
    while ($existing) {
        wp_unschedule_event($existing, NP_ORDER_HUB_PRINT_QUEUE_EVENT, $args);
        $existing = wp_next_scheduled(NP_ORDER_HUB_PRINT_QUEUE_EVENT, $args);
    }
    wp_schedule_single_event($run_at_ts, NP_ORDER_HUB_PRINT_QUEUE_EVENT, $args);
    return $run_at_ts;
}

function np_order_hub_print_queue_queue_order($store, $record, $reason = 'webhook') {
    if (!is_array($store) || !is_array($record)) {
        return;
    }
    $store_key = isset($record['store_key']) ? sanitize_key((string) $record['store_key']) : '';
    $order_id = isset($record['order_id']) ? absint($record['order_id']) : 0;
    $job_key = np_order_hub_print_queue_job_key($store_key, $order_id);
    if ($job_key === '') {
        return;
    }

    $payload = np_order_hub_print_queue_extract_payload($record);
    if (!np_order_hub_print_queue_should_enqueue($store, $record, $payload)) {
        return;
    }

    $existing = np_order_hub_print_queue_get_job($job_key);
    if (is_array($existing) && !empty($existing['status']) && in_array($existing['status'], array('ready', 'completed'), true)) {
        return;
    }

    $now_gmt = gmdate('Y-m-d H:i:s');
    $run_at = time() + NP_ORDER_HUB_PRINT_QUEUE_DELAY_SECONDS;
    $scheduled_ts = np_order_hub_print_queue_schedule_event($job_key, $run_at);

    $job = is_array($existing) ? $existing : array();
    $job['job_key'] = $job_key;
    $job['store_key'] = $store_key;
    $job['store_name'] = isset($record['store_name']) ? (string) $record['store_name'] : (isset($store['name']) ? (string) $store['name'] : '');
    $job['order_id'] = $order_id;
    $job['order_number'] = isset($record['order_number']) ? (string) $record['order_number'] : (string) $order_id;
    $job['record_id'] = isset($record['id']) ? absint($record['id']) : 0;
    $job['status'] = 'pending';
    $job['attempts'] = isset($job['attempts']) ? (int) $job['attempts'] : 0;
    $job['max_attempts'] = NP_ORDER_HUB_PRINT_QUEUE_MAX_ATTEMPTS;
    $job['scheduled_for_gmt'] = gmdate('Y-m-d H:i:s', (int) $scheduled_ts);
    $job['updated_at_gmt'] = $now_gmt;
    if (empty($job['created_at_gmt'])) {
        $job['created_at_gmt'] = $now_gmt;
    }
    $job['last_error'] = '';
    np_order_hub_print_queue_append_log($job, 'Queued (' . sanitize_text_field($reason) . ') for ' . $job['scheduled_for_gmt']);
    np_order_hub_print_queue_set_job($job_key, $job);
}
