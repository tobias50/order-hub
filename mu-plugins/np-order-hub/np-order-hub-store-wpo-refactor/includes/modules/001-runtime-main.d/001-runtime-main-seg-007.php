<?php
function np_order_hub_wpo_parse_order_ids($raw) {
    if (is_array($raw)) {
        $ids = array_map('absint', $raw);
    } else {
        $raw = (string) $raw;
        $ids = $raw !== '' ? array_map('absint', explode(',', $raw)) : array();
    }
    $ids = array_filter($ids, function ($value) {
        return $value > 0;
    });
    return array_values(array_unique($ids));
}

function np_order_hub_wpo_get_pdf_bytes($document) {
    if (is_object($document) && method_exists($document, 'get_pdf')) {
        $pdf = $document->get_pdf();
        if (!empty($pdf)) {
            return $pdf;
        }
    }
    if (is_object($document) && method_exists($document, 'output_pdf')) {
        ob_start();
        $document->output_pdf();
        $pdf = ob_get_clean();
        if (!empty($pdf)) {
            return $pdf;
        }
    }
    return '';
}

function np_order_hub_wpo_try_bulk_document($orders, $order_ids) {
    if (!function_exists('wcpdf_get_document')) {
        return null;
    }
    $candidates = array(
        array('label' => 'orders', 'value' => $orders),
        array('label' => 'order_ids', 'value' => $order_ids),
    );
    foreach ($candidates as $candidate) {
        if (empty($candidate['value'])) {
            continue;
        }
        try {
            $document = wcpdf_get_document('packing-slip', $candidate['value']);
            if (is_wp_error($document)) {
                np_order_hub_wpo_log('bulk_document_error', array(
                    'input' => $candidate['label'],
                    'code' => $document->get_error_code(),
                    'message' => $document->get_error_message(),
                ));
                continue;
            }
            if ($document) {
                np_order_hub_wpo_log('bulk_document_ok', array('input' => $candidate['label']));
                return $document;
            }
        } catch (Throwable $e) {
            np_order_hub_wpo_log('bulk_document_error', array(
                'input' => $candidate['label'],
                'message' => $e->getMessage(),
            ));
        }
    }
    return null;
}

function np_order_hub_wpo_merge_pdfs($pdf_paths) {
    if (empty($pdf_paths)) {
        return new WP_Error('empty_pdfs', 'No PDFs to merge.');
    }
    $qpdf = function_exists('shell_exec') ? trim((string) shell_exec('command -v qpdf 2>/dev/null')) : '';
    if ($qpdf) {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellcmd($qpdf) . ' --empty --pages';
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' -- ' . escapeshellarg($out) . ' 2>/dev/null';
            @shell_exec($cmd);
            if (is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (is_file($out)) {
                @unlink($out);
            }
        }
    }

    $gs = function_exists('shell_exec') ? trim((string) shell_exec('command -v gs 2>/dev/null')) : '';
    if ($gs) {
        $out = wp_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellcmd($gs) . ' -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=' . escapeshellarg($out);
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' 2>/dev/null';
            @shell_exec($cmd);
            if (is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (is_file($out)) {
                @unlink($out);
            }
        }
    }

    return new WP_Error('merge_unavailable', 'Could not merge PDFs on this server.');
}

function np_order_hub_wpo_packing_slips(WP_REST_Request $request) {
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }
    if (!np_order_hub_wpo_check_token($token)) {
        np_order_hub_wpo_log('packing_slips_unauthorized');
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }
    $order_ids = np_order_hub_wpo_parse_order_ids($request->get_param('order_ids'));
    if (empty($order_ids)) {
        return new WP_REST_Response(array('error' => 'missing_order_ids'), 400);
    }

    $orders = array();
    foreach ($order_ids as $order_id) {
        $order = wc_get_order($order_id);
        if ($order) {
            $orders[] = $order;
        }
    }
    if (empty($orders)) {
        return new WP_REST_Response(array('error' => 'orders_not_found'), 404);
    }

    $bulk_document = np_order_hub_wpo_try_bulk_document($orders, $order_ids);
    if ($bulk_document) {
        $bulk_pdf = np_order_hub_wpo_get_pdf_bytes($bulk_document);
        if ($bulk_pdf !== '') {
            nocache_headers();
            header('Content-Type: application/pdf');
            header('Content-Disposition: inline; filename="packing-slips-' . gmdate('Ymd-His') . '.pdf"');
            echo $bulk_pdf;
            exit;
        }
    }

    $pdf_paths = array();
    foreach ($orders as $order) {
        $document = np_order_hub_get_wpo_document($order);
        if (!$document || is_wp_error($document)) {
            np_order_hub_wpo_log('packing_slips_document_missing', array(
                'order_id' => $order->get_id(),
            ));
            continue;
        }
        $pdf_bytes = np_order_hub_wpo_get_pdf_bytes($document);
        if ($pdf_bytes === '') {
            np_order_hub_wpo_log('packing_slips_pdf_empty', array(
                'order_id' => $order->get_id(),
            ));
            continue;
        }
        $tmp = wp_tempnam('packing-slip-' . $order->get_id());
        if ($tmp) {
            $path = $tmp . '.pdf';
            @rename($tmp, $path);
            file_put_contents($path, $pdf_bytes);
            $pdf_paths[] = $path;
        }
    }

    $merged = np_order_hub_wpo_merge_pdfs($pdf_paths);
    foreach ($pdf_paths as $path) {
        if (is_file($path)) {
            @unlink($path);
        }
    }

    if (is_wp_error($merged)) {
        np_order_hub_wpo_log('packing_slips_merge_failed', array(
            'code' => $merged->get_error_code(),
            'message' => $merged->get_error_message(),
        ));
        return new WP_REST_Response(array('error' => $merged->get_error_message()), 500);
    }

    if (!is_file($merged)) {
        return new WP_REST_Response(array('error' => 'merge_failed'), 500);
    }

    nocache_headers();
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="packing-slips-' . gmdate('Ymd-His') . '.pdf"');
    readfile($merged);
    @unlink($merged);
    exit;
}

function np_order_hub_wpo_update_order_status(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $status = sanitize_key((string) $request->get_param('status'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('status_update_request', array(
        'order_id' => $order_id,
        'status' => $status,
        'token_present' => $token !== '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1 || $status === '') {
        return new WP_REST_Response(array('error' => 'missing_params'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }
    $order = wc_get_order($order_id);
    if (!$order) {
        return new WP_REST_Response(array('error' => 'order_not_found'), 404);
    }
    $allowed = array('pending', 'processing', 'restordre', 'completed', 'on-hold', 'cancelled', 'refunded', 'reklamasjon', 'failed');
    if (!in_array($status, $allowed, true)) {
        return new WP_REST_Response(array('error' => 'invalid_status'), 400);
    }
    $order->update_status($status, 'Updated from Order Hub', true);
    return new WP_REST_Response(array(
        'status' => 'ok',
        'order_id' => $order_id,
        'new_status' => $status,
    ), 200);
}

function np_order_hub_wpo_order_exists(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('order_exists_request', array(
        'order_id' => $order_id,
        'token_present' => $token !== '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1) {
        return new WP_REST_Response(array('error' => 'missing_order_id'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }

    $order = wc_get_order($order_id);
    if (!$order || !is_a($order, 'WC_Order')) {
        return new WP_REST_Response(array(
            'status' => 'not_found',
            'exists' => false,
            'order_id' => $order_id,
        ), 404);
    }

    $status = method_exists($order, 'get_status') ? sanitize_key((string) $order->get_status()) : '';
    if ($status === 'trash' || $status === 'auto-draft') {
        return new WP_REST_Response(array(
            'status' => 'not_found',
            'exists' => false,
            'order_id' => $order_id,
        ), 404);
    }

    return new WP_REST_Response(array(
        'status' => 'ok',
        'exists' => true,
        'order_id' => $order_id,
        'order_number' => method_exists($order, 'get_order_number') ? (string) $order->get_order_number() : (string) $order_id,
    ), 200);
}

function np_order_hub_wpo_order_state(WP_REST_Request $request) {
    $order_id = absint($request->get_param('order_id'));
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }

    np_order_hub_wpo_log('order_state_request', array(
        'order_id' => $order_id,
        'token_present' => $token !== '',
    ));

    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if ($order_id < 1) {
        return new WP_REST_Response(array('error' => 'missing_order_id'), 400);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }

    $order = wc_get_order($order_id);
    if (!$order || !is_a($order, 'WC_Order')) {
        return new WP_REST_Response(array(
            'status' => 'not_found',
            'exists' => false,
            'order_id' => $order_id,
        ), 404);
    }

    $status = method_exists($order, 'get_status') ? sanitize_key((string) $order->get_status()) : '';
    if ($status === 'trash' || $status === 'auto-draft') {
        return new WP_REST_Response(array(
            'status' => 'not_found',
            'exists' => false,
            'order_id' => $order_id,
        ), 404);
    }

    $currency = method_exists($order, 'get_currency') ? sanitize_text_field((string) $order->get_currency()) : '';
    $total = method_exists($order, 'get_total') ? (float) $order->get_total() : 0.0;
    $created = method_exists($order, 'get_date_created') ? $order->get_date_created() : null;
    $modified = method_exists($order, 'get_date_modified') ? $order->get_date_modified() : null;

    return new WP_REST_Response(array(
        'status' => 'ok',
        'exists' => true,
        'order_id' => $order_id,
        'order_number' => method_exists($order, 'get_order_number') ? (string) $order->get_order_number() : (string) $order_id,
        'order_status' => $status,
        'currency' => $currency,
        'total' => wc_format_decimal($total, wc_get_price_decimals()),
        'date_created' => np_order_hub_wpo_iso_datetime($created, false),
        'date_created_gmt' => np_order_hub_wpo_iso_datetime($created, true),
        'date_modified' => np_order_hub_wpo_iso_datetime($modified, false),
        'date_modified_gmt' => np_order_hub_wpo_iso_datetime($modified, true),
    ), 200);
}

function np_order_hub_wpo_export_order_line_items($order) {
    $items = array();
    if (!is_object($order) || !method_exists($order, 'get_items')) {
        return $items;
    }
    foreach ($order->get_items('line_item') as $item_id => $item) {
        if (!is_object($item)) {
            continue;
        }
        $product = method_exists($item, 'get_product') ? $item->get_product() : null;
        $items[] = array(
            'id' => (int) $item_id,
            'name' => sanitize_text_field((string) $item->get_name()),
            'product_id' => method_exists($item, 'get_product_id') ? (int) $item->get_product_id() : 0,
            'variation_id' => method_exists($item, 'get_variation_id') ? (int) $item->get_variation_id() : 0,
            'quantity' => method_exists($item, 'get_quantity') ? (int) $item->get_quantity() : 0,
            'total' => wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
            'subtotal' => wc_format_decimal((float) $item->get_subtotal(), wc_get_price_decimals()),
            'sku' => (is_object($product) && method_exists($product, 'get_sku')) ? sanitize_text_field((string) $product->get_sku()) : '',
        );
    }
    return $items;
}

function np_order_hub_wpo_export_order_shipping_lines($order) {
    $items = array();
    if (!is_object($order) || !method_exists($order, 'get_items')) {
        return $items;
    }
    foreach ($order->get_items('shipping') as $item_id => $item) {
        if (!is_object($item)) {
            continue;
        }
        $items[] = array(
            'id' => (int) $item_id,
            'method_title' => method_exists($item, 'get_name') ? sanitize_text_field((string) $item->get_name()) : '',
            'method_id' => method_exists($item, 'get_method_id') ? sanitize_key((string) $item->get_method_id()) : '',
            'total' => wc_format_decimal((float) $item->get_total(), wc_get_price_decimals()),
        );
    }
    return $items;
}

function np_order_hub_wpo_export_order_payload($order) {
    if (!is_object($order) || !method_exists($order, 'get_id')) {
        return array();
    }
    $created = method_exists($order, 'get_date_created') ? $order->get_date_created() : null;
    $modified = method_exists($order, 'get_date_modified') ? $order->get_date_modified() : null;

    return array(
        'id' => (int) $order->get_id(),
        'number' => method_exists($order, 'get_order_number') ? (string) $order->get_order_number() : (string) $order->get_id(),
        'status' => method_exists($order, 'get_status') ? sanitize_key((string) $order->get_status()) : '',
        'currency' => method_exists($order, 'get_currency') ? sanitize_text_field((string) $order->get_currency()) : '',
        'total' => method_exists($order, 'get_total') ? wc_format_decimal((float) $order->get_total(), wc_get_price_decimals()) : '0',
        'date_created' => np_order_hub_wpo_iso_datetime($created, false),
        'date_created_gmt' => np_order_hub_wpo_iso_datetime($created, true),
        'date_modified' => np_order_hub_wpo_iso_datetime($modified, false),
        'date_modified_gmt' => np_order_hub_wpo_iso_datetime($modified, true),
        'billing' => array(
            'first_name' => method_exists($order, 'get_billing_first_name') ? sanitize_text_field((string) $order->get_billing_first_name()) : '',
            'last_name' => method_exists($order, 'get_billing_last_name') ? sanitize_text_field((string) $order->get_billing_last_name()) : '',
            'company' => method_exists($order, 'get_billing_company') ? sanitize_text_field((string) $order->get_billing_company()) : '',
            'email' => method_exists($order, 'get_billing_email') ? sanitize_email((string) $order->get_billing_email()) : '',
            'phone' => method_exists($order, 'get_billing_phone') ? sanitize_text_field((string) $order->get_billing_phone()) : '',
        ),
        'shipping' => array(
            'first_name' => method_exists($order, 'get_shipping_first_name') ? sanitize_text_field((string) $order->get_shipping_first_name()) : '',
            'last_name' => method_exists($order, 'get_shipping_last_name') ? sanitize_text_field((string) $order->get_shipping_last_name()) : '',
            'company' => method_exists($order, 'get_shipping_company') ? sanitize_text_field((string) $order->get_shipping_company()) : '',
        ),
        'line_items' => np_order_hub_wpo_export_order_line_items($order),
        'shipping_lines' => np_order_hub_wpo_export_order_shipping_lines($order),
    );
}

function np_order_hub_wpo_orders_export(WP_REST_Request $request) {
    $token = (string) $request->get_param('token');
    if ($token === '') {
        $token = (string) $request->get_header('x-np-order-hub-token');
    }
    if (!np_order_hub_wpo_check_token($token)) {
        return new WP_REST_Response(array('error' => 'unauthorized'), 401);
    }
    if (!function_exists('wc_get_orders')) {
        return new WP_REST_Response(array('error' => 'woocommerce_missing'), 500);
    }

    $status_raw = (string) $request->get_param('status');
    if ($status_raw === '') {
        $status_raw = 'processing';
    }
    $statuses = array();
    foreach (explode(',', $status_raw) as $status_item) {
        $status = sanitize_key((string) $status_item);
        if ($status === '') {
            continue;
        }
        if (strpos($status, 'wc-') === 0) {
            $status = substr($status, 3);
        }
        if ($status !== '') {
            $statuses[] = $status;
        }
    }
    $statuses = array_values(array_unique($statuses));
    if (empty($statuses)) {
        $statuses = array('processing');
    }

    $per_page = absint($request->get_param('per_page'));
    if ($per_page < 1) {
        $per_page = 100;
    } elseif ($per_page > 200) {
        $per_page = 200;
    }
    $page = absint($request->get_param('page'));
    if ($page < 1) {
        $page = 1;
    }

    $query = wc_get_orders(array(
        'status' => $statuses,
        'limit' => $per_page,
        'page' => $page,
        'orderby' => 'date',
        'order' => 'DESC',
        'paginate' => true,
        'return' => 'objects',
    ));

    $orders = array();
    $objects = array();
    $total = 0;
    $total_pages = 1;

    if (is_array($query) && array_key_exists('orders', $query)) {
        $objects = is_array($query['orders']) ? $query['orders'] : array();
        $total = isset($query['total']) ? (int) $query['total'] : 0;
        $total_pages = isset($query['max_num_pages']) ? (int) $query['max_num_pages'] : 1;
    } elseif (is_array($query)) {
        $objects = $query;
    }

    foreach ($objects as $order) {
        $payload = np_order_hub_wpo_export_order_payload($order);
        if (!empty($payload)) {
            $orders[] = $payload;
        }
    }

    return new WP_REST_Response(array(
        'status' => 'ok',
        'page' => $page,
        'per_page' => $per_page,
        'total' => $total,
        'total_pages' => $total_pages < 1 ? 1 : $total_pages,
        'orders' => $orders,
    ), 200);
}

function np_order_hub_wpo_get_request_params(WP_REST_Request $request) {
    $params = $request->get_json_params();
    if (!is_array($params) || empty($params)) {
        $params = $request->get_params();
    }
    return is_array($params) ? $params : array();
}
