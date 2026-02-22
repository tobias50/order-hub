<?php
function np_order_hub_print_queue_schedule_retry($job_key, &$job, $error_message) {
    $attempts = isset($job['attempts']) ? (int) $job['attempts'] : 0;
    $max_attempts = isset($job['max_attempts']) ? (int) $job['max_attempts'] : NP_ORDER_HUB_PRINT_QUEUE_MAX_ATTEMPTS;
    $job['last_error'] = sanitize_text_field((string) $error_message);
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');

    if ($attempts >= $max_attempts) {
        $job['status'] = 'failed';
        np_order_hub_print_queue_append_log($job, 'Failed permanently: ' . $job['last_error']);
        np_order_hub_print_queue_set_job($job_key, $job);
        return;
    }

    $job['status'] = 'retry';
    $next_ts = time() + NP_ORDER_HUB_PRINT_QUEUE_RETRY_SECONDS;
    $scheduled_ts = np_order_hub_print_queue_schedule_event($job_key, $next_ts);
    $job['scheduled_for_gmt'] = gmdate('Y-m-d H:i:s', (int) $scheduled_ts);
    np_order_hub_print_queue_append_log($job, 'Retry scheduled: ' . $job['last_error']);
    np_order_hub_print_queue_set_job($job_key, $job);
}

function np_order_hub_print_queue_mark_failed($job_key, &$job, $reason) {
    $job['status'] = 'failed';
    $job['last_error'] = sanitize_text_field((string) $reason);
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    np_order_hub_print_queue_append_log($job, 'Failed: ' . $job['last_error']);
    np_order_hub_print_queue_set_job($job_key, $job);
}

function np_order_hub_print_queue_mark_skipped($job_key, &$job, $reason) {
    $job['status'] = 'skipped';
    $job['last_error'] = sanitize_text_field((string) $reason);
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    np_order_hub_print_queue_append_log($job, 'Skipped: ' . $job['last_error']);
    np_order_hub_print_queue_set_job($job_key, $job);
}

function np_order_hub_print_queue_should_retry_error($error) {
    if (!is_wp_error($error)) {
        return true;
    }
    $non_retryable_codes = array(
        'missing_api_credentials',
        'missing_endpoint',
        'print_packing_url_missing',
        'print_upload_dir_error',
        'print_upload_dir_missing',
        'print_upload_dir_create_failed',
        'print_order_missing',
    );
    $code = (string) $error->get_error_code();
    return !in_array($code, $non_retryable_codes, true);
}

function np_order_hub_print_queue_get_upload_dir() {
    $uploads = wp_upload_dir();
    if (!empty($uploads['error'])) {
        return new WP_Error('print_upload_dir_error', (string) $uploads['error']);
    }
    if (empty($uploads['basedir']) || empty($uploads['baseurl'])) {
        return new WP_Error('print_upload_dir_missing', 'Upload directory is not configured.');
    }
    $dir = trailingslashit((string) $uploads['basedir']) . 'np-order-hub-print-jobs';
    $url = trailingslashit((string) $uploads['baseurl']) . 'np-order-hub-print-jobs';
    if (!wp_mkdir_p($dir)) {
        return new WP_Error('print_upload_dir_create_failed', 'Could not create print jobs directory.');
    }
    return array(
        'dir' => $dir,
        'url' => $url,
    );
}

function np_order_hub_print_queue_move_pdf_to_job_dir($tmp_pdf_path, $job) {
    if (!is_string($tmp_pdf_path) || $tmp_pdf_path === '' || !is_file($tmp_pdf_path)) {
        return new WP_Error('print_tmp_missing', 'Temporary print PDF is missing.');
    }
    $upload_dir = np_order_hub_print_queue_get_upload_dir();
    if (is_wp_error($upload_dir)) {
        return $upload_dir;
    }
    $store_key = isset($job['store_key']) ? sanitize_key((string) $job['store_key']) : 'store';
    $order_id = isset($job['order_id']) ? absint($job['order_id']) : 0;
    $timestamp = gmdate('Ymd-His');
    $filename = sanitize_file_name('order-' . $store_key . '-' . $order_id . '-' . $timestamp . '.pdf');
    if ($filename === '' || substr($filename, -4) !== '.pdf') {
        $filename = 'order-' . $store_key . '-' . $order_id . '-' . $timestamp . '.pdf';
    }
    $target = trailingslashit($upload_dir['dir']) . $filename;
    if (!@rename($tmp_pdf_path, $target)) {
        if (!@copy($tmp_pdf_path, $target)) {
            return new WP_Error('print_store_failed', 'Could not move print PDF to uploads.');
        }
        @unlink($tmp_pdf_path);
    }
    return array(
        'path' => $target,
        'url' => trailingslashit($upload_dir['url']) . $filename,
        'filename' => $filename,
    );
}

function np_order_hub_fetch_store_order_via_wc_api($store, $order_id) {
    $order_id = absint($order_id);
    if (!is_array($store) || $order_id < 1) {
        return new WP_Error('print_order_missing', 'Store or order ID missing.');
    }
    $response = np_order_hub_wc_api_request($store, 'orders/' . $order_id, array(), 25);
    if (is_wp_error($response)) {
        return $response;
    }
    $code = (int) wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        return np_order_hub_wc_api_error_response($code, $body);
    }
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded)) {
        return np_order_hub_wc_api_bad_response($body);
    }
    return $decoded;
}

function np_order_hub_collect_urls_from_data($value, $path = '', &$items = array()) {
    if (is_array($value)) {
        foreach ($value as $key => $child) {
            $child_path = $path === '' ? (string) $key : ($path . '.' . $key);
            np_order_hub_collect_urls_from_data($child, $child_path, $items);
        }
        return;
    }
    if (!is_string($value)) {
        return;
    }
    $text = trim($value);
    if ($text === '') {
        return;
    }
    if (filter_var($text, FILTER_VALIDATE_URL)) {
        $items[] = array(
            'url' => esc_url_raw($text),
            'path' => (string) $path,
        );
        return;
    }
    if (strpos($text, 'http://') === false && strpos($text, 'https://') === false) {
        return;
    }
    if (preg_match_all('~https?://[^\s"\'<>]+~i', $text, $matches)) {
        foreach ((array) $matches[0] as $url) {
            $url = esc_url_raw((string) $url);
            if ($url === '') {
                continue;
            }
            $items[] = array(
                'url' => $url,
                'path' => (string) $path,
            );
        }
    }
}

function np_order_hub_score_label_url_candidate($candidate, $packing_url = '') {
    if (!is_array($candidate) || empty($candidate['url'])) {
        return -999;
    }
    $url = strtolower((string) $candidate['url']);
    $path = strtolower(isset($candidate['path']) ? (string) $candidate['path'] : '');
    $combined = $url . ' ' . $path;
    if ($packing_url !== '' && strtolower($packing_url) === $url) {
        return -999;
    }

    $score = 0;
    if (strpos($combined, 'proteria') !== false) {
        $score += 70;
    }
    if (preg_match('/etikett|label|frakt|shipping|shipment|consignment|waybill|awb/i', $combined)) {
        $score += 50;
    }
    if (preg_match('/\\.pdf(\\?|$)/i', $url)) {
        $score += 30;
    }
    if (strpos($combined, 'packing-slip') !== false || strpos($combined, 'wpo_wcpdf') !== false) {
        $score -= 80;
    }
    if (strpos($combined, 'invoice') !== false) {
        $score -= 40;
    }
    return $score;
}

function np_order_hub_extract_proteria_label_url($order_data, $packing_url = '') {
    if (!is_array($order_data)) {
        return '';
    }
    $items = array();
    np_order_hub_collect_urls_from_data($order_data, '', $items);
    if (empty($items)) {
        return '';
    }

    $best_url = '';
    $best_score = -999;
    foreach ($items as $item) {
        $score = np_order_hub_score_label_url_candidate($item, $packing_url);
        if ($score > $best_score) {
            $best_score = $score;
            $best_url = (string) $item['url'];
        }
    }
    if ($best_score < 40) {
        return '';
    }
    return $best_url;
}

function np_order_hub_fetch_pdf_document($url, $document_name = 'Document') {
    $url = trim((string) $url);
    if ($url === '') {
        return new WP_Error('pdf_missing_url', $document_name . ' URL missing.');
    }
    $response = wp_remote_get($url, array(
        'timeout' => 45,
        'redirection' => 3,
        'headers' => array(
            'Accept' => 'application/pdf',
        ),
    ));
    if (is_wp_error($response)) {
        return $response;
    }
    $code = (int) wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    if ($code < 200 || $code >= 300) {
        return new WP_Error('pdf_http_' . $code, $document_name . ' request failed (HTTP ' . $code . ').');
    }
    if (!np_order_hub_pdf_bytes_look_valid($body)) {
        $content_type = wp_remote_retrieve_header($response, 'content-type');
        $message = $document_name . ' response was not a PDF.';
        if (is_string($content_type) && $content_type !== '') {
            $message .= ' (' . $content_type . ')';
        }
        return new WP_Error('pdf_invalid', $message);
    }
    return $body;
}

function np_order_hub_print_queue_fetch_label_pdf($store, $order_id, $packing_url = '', $payload = array()) {
    $order = np_order_hub_fetch_store_order_via_wc_api($store, $order_id);
    if (is_wp_error($order)) {
        return $order;
    }
    $source = $order;
    if (is_array($payload) && !empty($payload)) {
        $source = array(
            'payload' => $payload,
            'order' => $order,
        );
    }
    $label_url = np_order_hub_extract_proteria_label_url($source, $packing_url);
    if ($label_url === '') {
        $label_url = np_order_hub_build_shipping_label_url($store, $order_id);
    }
    if ($label_url === '') {
        return new WP_Error('print_label_missing', 'Proteria label URL not found on order yet.');
    }
    $pdf = np_order_hub_fetch_pdf_document($label_url, 'Shipping label');
    if (is_wp_error($pdf)) {
        return $pdf;
    }
    return array(
        'url' => $label_url,
        'pdf' => $pdf,
    );
}