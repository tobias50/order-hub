<?php
function np_order_hub_print_queue_build_bundle($store, $record, $payload) {
    $order_id = isset($record['order_id']) ? absint($record['order_id']) : 0;
    $order_number = isset($record['order_number']) ? (string) $record['order_number'] : (string) $order_id;
    $packing_url = np_order_hub_build_packing_slip_url($store, $order_id, $order_number, $payload);
    if ($packing_url === '') {
        return new WP_Error('print_packing_url_missing', 'Packing slip URL missing.');
    }

    $packing_pdf = np_order_hub_fetch_pdf_document($packing_url, 'Packing slip');
    if (is_wp_error($packing_pdf)) {
        return $packing_pdf;
    }

    $label_data = np_order_hub_print_queue_fetch_label_pdf($store, $order_id, $packing_url, $payload);
    if (is_wp_error($label_data)) {
        return $label_data;
    }

    $tmp_packing = np_order_hub_tempnam('np-order-hub-packing');
    $tmp_label = np_order_hub_tempnam('np-order-hub-label');
    if (!$tmp_packing || !$tmp_label) {
        if ($tmp_packing && is_file($tmp_packing)) {
            @unlink($tmp_packing);
        }
        if ($tmp_label && is_file($tmp_label)) {
            @unlink($tmp_label);
        }
        return new WP_Error('print_tmp_failed', 'Could not create temp files for print merge.');
    }

    $packing_path = $tmp_packing . '.pdf';
    $label_path = $tmp_label . '.pdf';
    @rename($tmp_packing, $packing_path);
    @rename($tmp_label, $label_path);
    file_put_contents($packing_path, $packing_pdf);
    file_put_contents($label_path, $label_data['pdf']);

    $base_size = np_order_hub_get_pdf_first_page_size_fpdi($packing_path);
    if (is_wp_error($base_size)) {
        $merged = np_order_hub_merge_pdfs(array($packing_path, $label_path));
    } else {
        $merged = np_order_hub_merge_pdfs_fpdi(
            array($packing_path, $label_path),
            array('fixed_page_size' => $base_size)
        );
        if (is_wp_error($merged)) {
            $merged = np_order_hub_merge_pdfs(array($packing_path, $label_path));
        }
    }
    @unlink($packing_path);
    @unlink($label_path);
    if (is_wp_error($merged)) {
        return $merged;
    }

    return array(
        'path' => $merged,
        'packing_url' => $packing_url,
        'label_url' => isset($label_data['url']) ? (string) $label_data['url'] : '',
    );
}

function np_order_hub_process_print_job($job_key) {
    $job_key = sanitize_text_field((string) $job_key);
    if ($job_key === '') {
        return;
    }
    $job = np_order_hub_print_queue_get_job($job_key);
    if (!is_array($job)) {
        return;
    }

    $lock_key = 'np_order_hub_print_lock_' . substr(md5($job_key), 0, 20);
    if (get_transient($lock_key)) {
        return;
    }
    set_transient($lock_key, 1, 90);

    $job['status'] = 'running';
    $job['attempts'] = isset($job['attempts']) ? ((int) $job['attempts'] + 1) : 1;
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    $job['last_error'] = '';
    np_order_hub_print_queue_append_log($job, 'Processing attempt ' . $job['attempts']);
    np_order_hub_print_queue_set_job($job_key, $job);

    $store_key = isset($job['store_key']) ? sanitize_key((string) $job['store_key']) : '';
    $order_id = isset($job['order_id']) ? absint($job['order_id']) : 0;
    $store = np_order_hub_get_store_by_key($store_key);
    $record = np_order_hub_print_queue_get_order_record($store_key, $order_id);

    if (!$store || !$record) {
        np_order_hub_print_queue_mark_skipped($job_key, $job, 'Store or order not found in hub.');
        delete_transient($lock_key);
        return;
    }

    $payload = np_order_hub_print_queue_extract_payload($record);
    if (!np_order_hub_print_queue_should_enqueue($store, $record, $payload)) {
        np_order_hub_print_queue_mark_skipped($job_key, $job, 'Order no longer eligible for auto print.');
        delete_transient($lock_key);
        return;
    }

    try {
        $bundle = np_order_hub_print_queue_build_bundle($store, $record, $payload);
    } catch (Throwable $e) {
        np_order_hub_print_queue_schedule_retry($job_key, $job, 'Exception while building print bundle: ' . $e->getMessage());
        delete_transient($lock_key);
        return;
    }
    if (is_wp_error($bundle)) {
        if (np_order_hub_print_queue_should_retry_error($bundle)) {
            np_order_hub_print_queue_schedule_retry($job_key, $job, $bundle->get_error_message());
        } else {
            np_order_hub_print_queue_mark_failed($job_key, $job, $bundle->get_error_message());
        }
        delete_transient($lock_key);
        return;
    }

    try {
        $stored = np_order_hub_print_queue_move_pdf_to_job_dir((string) $bundle['path'], $job);
    } catch (Throwable $e) {
        np_order_hub_print_queue_schedule_retry($job_key, $job, 'Exception while storing print PDF: ' . $e->getMessage());
        delete_transient($lock_key);
        return;
    }
    if (is_wp_error($stored)) {
        if (np_order_hub_print_queue_should_retry_error($stored)) {
            np_order_hub_print_queue_schedule_retry($job_key, $job, $stored->get_error_message());
        } else {
            np_order_hub_print_queue_mark_failed($job_key, $job, $stored->get_error_message());
        }
        delete_transient($lock_key);
        return;
    }

    if (!empty($job['document_path']) && is_string($job['document_path']) && is_file($job['document_path']) && $job['document_path'] !== $stored['path']) {
        @unlink($job['document_path']);
    }

    $job['status'] = 'ready';
    $job['record_id'] = isset($record['id']) ? absint($record['id']) : 0;
    $job['order_number'] = isset($record['order_number']) ? (string) $record['order_number'] : (string) $order_id;
    $job['document_path'] = (string) $stored['path'];
    $job['document_url'] = (string) $stored['url'];
    $job['document_filename'] = (string) $stored['filename'];
    $job['packing_url'] = isset($bundle['packing_url']) ? (string) $bundle['packing_url'] : '';
    $job['label_url'] = isset($bundle['label_url']) ? (string) $bundle['label_url'] : '';
    $job['last_error'] = '';
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    $job['scheduled_for_gmt'] = '';
    np_order_hub_print_queue_append_log($job, 'Ready: combined packing slip + shipping label');
    np_order_hub_print_queue_set_job($job_key, $job);
    delete_transient($lock_key);
}

function np_order_hub_print_queue_run_due_jobs($limit = 10) {
    $jobs = np_order_hub_print_queue_get_jobs();
    if (empty($jobs)) {
        return 0;
    }
    $now = time();
    $ran = 0;
    foreach ($jobs as $job_key => $job) {
        if ($ran >= $limit) {
            break;
        }
        if (!is_array($job)) {
            continue;
        }
        $status = isset($job['status']) ? (string) $job['status'] : '';
        if (!in_array($status, array('pending', 'retry', 'running'), true)) {
            continue;
        }
        $scheduled = isset($job['scheduled_for_gmt']) ? strtotime((string) $job['scheduled_for_gmt']) : 0;
        if ($scheduled > $now) {
            continue;
        }
        np_order_hub_process_print_job((string) $job_key);
        $ran++;
    }
    return $ran;
}

function np_order_hub_print_queue_retry_now($job_key) {
    $job_key = sanitize_text_field((string) $job_key);
    if ($job_key === '') {
        return new WP_Error('print_retry_missing_key', 'Missing print job key.');
    }
    $job = np_order_hub_print_queue_get_job($job_key);
    if (!is_array($job)) {
        return new WP_Error('print_retry_missing_job', 'Print job not found.');
    }
    $job['status'] = 'pending';
    $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
    $job['last_error'] = '';
    // Clear any stale print-agent claim before forcing a rebuild retry.
    $job['claim_id'] = '';
    $job['claim_by'] = '';
    $job['claim_expires_gmt'] = '';
    $scheduled = np_order_hub_print_queue_schedule_event($job_key, time() + 5);
    $job['scheduled_for_gmt'] = gmdate('Y-m-d H:i:s', (int) $scheduled);
    np_order_hub_print_queue_append_log($job, 'Manually queued for immediate retry.');
    np_order_hub_print_queue_set_job($job_key, $job);
    return true;
}

function np_order_hub_print_queue_release_stale_printing_jobs() {
    $jobs = np_order_hub_print_queue_get_jobs();
    if (empty($jobs)) {
        return 0;
    }
    $now = time();
    $changed = 0;
    foreach ($jobs as $job_key => &$job) {
        if (!is_array($job)) {
            continue;
        }
        $status = isset($job['status']) ? (string) $job['status'] : '';
        if ($status !== 'printing') {
            continue;
        }
        $expires = isset($job['claim_expires_gmt']) ? strtotime((string) $job['claim_expires_gmt']) : 0;
        if ($expires > 0 && $expires >= $now) {
            continue;
        }
        $job['status'] = 'ready';
        $job['claim_id'] = '';
        $job['claim_by'] = '';
        $job['claim_expires_gmt'] = '';
        $job['updated_at_gmt'] = gmdate('Y-m-d H:i:s');
        np_order_hub_print_queue_append_log($job, 'Claim expired. Returned to ready.');
        $changed++;
    }
    unset($job);
    if ($changed > 0) {
        np_order_hub_print_queue_save_jobs($jobs);
    }
    return $changed;
}

function np_order_hub_print_queue_build_agent_payload($job_key, $job) {
    if (!is_array($job)) {
        return array();
    }
    return array(
        'job_key' => (string) $job_key,
        'claim_id' => isset($job['claim_id']) ? (string) $job['claim_id'] : '',
        'status' => isset($job['status']) ? (string) $job['status'] : '',
        'store_key' => isset($job['store_key']) ? (string) $job['store_key'] : '',
        'store_name' => isset($job['store_name']) ? (string) $job['store_name'] : '',
        'order_id' => isset($job['order_id']) ? (int) $job['order_id'] : 0,
        'order_number' => isset($job['order_number']) ? (string) $job['order_number'] : '',
        'record_id' => isset($job['record_id']) ? (int) $job['record_id'] : 0,
        'document_url' => isset($job['document_url']) ? (string) $job['document_url'] : '',
        'document_filename' => isset($job['document_filename']) ? (string) $job['document_filename'] : '',
        'packing_url' => isset($job['packing_url']) ? (string) $job['packing_url'] : '',
        'label_url' => isset($job['label_url']) ? (string) $job['label_url'] : '',
        'attempts' => isset($job['attempts']) ? (int) $job['attempts'] : 0,
        'print_attempts' => isset($job['print_attempts']) ? (int) $job['print_attempts'] : 0,
        'updated_at_gmt' => isset($job['updated_at_gmt']) ? (string) $job['updated_at_gmt'] : '',
    );
}