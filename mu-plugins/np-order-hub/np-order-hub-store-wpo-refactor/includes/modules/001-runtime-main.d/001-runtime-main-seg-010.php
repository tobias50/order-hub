<?php
function np_order_hub_extract_access_key_from_url($url) {
    $url = (string) $url;
    if ($url === '') {
        return '';
    }
    $parsed = wp_parse_url($url);
    if (empty($parsed['query'])) {
        return '';
    }
    parse_str($parsed['query'], $params);
    if (empty($params['access_key'])) {
        return '';
    }
    return sanitize_text_field((string) $params['access_key']);
}

function np_order_hub_add_wpo_access_key($payload, $resource, $resource_id, $webhook_id) {
    np_order_hub_wpo_log('webhook_payload_start', array(
        'resource' => $resource,
        'resource_id' => $resource_id,
        'webhook_id' => $webhook_id,
    ));
    np_order_hub_wpo_log('webhook_payload_functions', array(
        'has_wcpdf_get_document' => function_exists('wcpdf_get_document'),
        'has_wpo_wcpdf_get_document' => function_exists('\\WPO\\wcpdf_get_document'),
        'has_wpo_wc_pdf_wcpdf_get_document' => function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document'),
        'has_wcpdf_get_document_link' => function_exists('wcpdf_get_document_link'),
        'has_wpo_wcpdf_get_document_link' => function_exists('\\WPO\\wcpdf_get_document_link'),
        'has_wpo_wc_pdf_wcpdf_get_document_link' => function_exists('\\WPO\\WC\\PDF_Invoices\\wcpdf_get_document_link'),
    ));
    if ($resource !== 'order') {
        np_order_hub_wpo_log('webhook_payload_skip_resource', array('resource' => $resource));
        return $payload;
    }
    if (!function_exists('wc_get_order')) {
        np_order_hub_wpo_log('webhook_payload_missing_wc_get_order');
        return $payload;
    }

    $order = wc_get_order($resource_id);
    if (!$order) {
        np_order_hub_wpo_log('webhook_payload_order_missing', array('resource_id' => $resource_id));
        return $payload;
    }

    $document = np_order_hub_get_wpo_document($order);
    if (!$document || is_wp_error($document)) {
        np_order_hub_wpo_log('webhook_payload_document_missing', array(
            'resource_id' => $resource_id,
            'is_error' => is_wp_error($document),
            'error_code' => is_wp_error($document) ? $document->get_error_code() : '',
            'error_message' => is_wp_error($document) ? $document->get_error_message() : '',
        ));
        return $payload;
    }
    np_order_hub_wpo_log('webhook_payload_document_class', array(
        'resource_id' => $resource_id,
        'class' => is_object($document) ? get_class($document) : gettype($document),
        'has_get_access_key' => is_object($document) && method_exists($document, 'get_access_key'),
        'has_get_document_link' => is_object($document) && method_exists($document, 'get_document_link'),
        'has_get_url' => is_object($document) && method_exists($document, 'get_url'),
    ));

    $access_key = '';
    if (is_object($document) && method_exists($document, 'get_access_key')) {
        $access_key = (string) $document->get_access_key();
    }
    np_order_hub_wpo_log('webhook_payload_access_key_from_document', array(
        'resource_id' => $resource_id,
        'access_key' => $access_key,
    ));

    if ($access_key === '') {
        $access_key = (string) $order->get_meta('_wcpdf_packing-slip_access_key', true);
        if ($access_key !== '') {
            np_order_hub_wpo_log('webhook_payload_access_key_from_meta', array(
                'resource_id' => $resource_id,
                'meta_key' => '_wcpdf_packing-slip_access_key',
                'access_key' => $access_key,
            ));
        }
    }
    if ($access_key === '') {
        $access_key = (string) $order->get_meta('_wcpdf_packing_slip_access_key', true);
        if ($access_key !== '') {
            np_order_hub_wpo_log('webhook_payload_access_key_from_meta', array(
                'resource_id' => $resource_id,
                'meta_key' => '_wcpdf_packing_slip_access_key',
                'access_key' => $access_key,
            ));
        }
    }
    np_order_hub_wpo_log('webhook_payload_meta_keys', array(
        'resource_id' => $resource_id,
        'meta_dash' => (string) $order->get_meta('_wcpdf_packing-slip_access_key', true),
        'meta_underscore' => (string) $order->get_meta('_wcpdf_packing_slip_access_key', true),
    ));

    $document_source = '';
    $document_url = np_order_hub_get_wpo_document_link($document, $order, $document_source);
    if ($document_url !== '') {
        $payload['np_wpo_packing_slip_url'] = $document_url;
    }
    np_order_hub_wpo_log('webhook_payload_document_url', array(
        'resource_id' => $resource_id,
        'document_url' => $document_url,
        'source' => $document_source,
    ));

    if ($access_key === '' && $document_url !== '') {
        $access_key = np_order_hub_extract_access_key_from_url($document_url);
        np_order_hub_wpo_log('webhook_payload_access_key_from_url', array(
            'resource_id' => $resource_id,
            'access_key' => $access_key,
        ));
    }

    if ($access_key !== '') {
        $payload['np_wpo_access_key'] = $access_key;
    }

    $reklamasjon_source = '';
    if (method_exists($order, 'get_meta')) {
        $reklamasjon_source = (string) $order->get_meta('_np_reklamasjon_source_order', true);
    }
    $is_reklamasjon = $reklamasjon_source !== '';
    if (!$is_reklamasjon && method_exists($order, 'get_status')) {
        $is_reklamasjon = $order->get_status() === 'reklamasjon';
    }
    if ($is_reklamasjon) {
        $payload['np_reklamasjon'] = true;
        if ($reklamasjon_source !== '') {
            $payload['np_reklamasjon_source_order'] = (int) $reklamasjon_source;
        }
    }

    $payload['np_order_hub_delivery_bucket'] = np_order_hub_wpo_get_default_delivery_bucket();

    np_order_hub_wpo_log('webhook_payload_done', array(
        'resource_id' => $resource_id,
        'has_access_key' => $access_key !== '',
        'has_packing_slip_url' => $document_url !== '',
    ));

    return $payload;
}
