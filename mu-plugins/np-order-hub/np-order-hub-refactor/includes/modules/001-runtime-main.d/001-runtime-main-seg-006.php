<?php
function np_order_hub_get_pdf_first_page_size_fpdi($path) {
    if (!is_string($path) || $path === '' || !is_file($path)) {
        return new WP_Error('pdf_size_missing', 'PDF path missing for size detection.');
    }
    if (!np_order_hub_require_fpdi()) {
        return new WP_Error('fpdi_missing', 'FPDI library missing.');
    }
    if (!class_exists('\\setasign\\Fpdi\\Fpdi')) {
        return new WP_Error('fpdi_missing', 'FPDI class not available.');
    }
    try {
        $probe = new \setasign\Fpdi\Fpdi();
        $pages = $probe->setSourceFile($path);
        if (!$pages || $pages < 1) {
            return new WP_Error('pdf_size_no_pages', 'PDF contains no pages.');
        }
        $tpl = $probe->importPage(1);
        $size = $probe->getTemplateSize($tpl);
        if (!is_array($size) || empty($size['width']) || empty($size['height'])) {
            return new WP_Error('pdf_size_invalid', 'Could not read PDF page size.');
        }
        return array(
            'width' => (float) $size['width'],
            'height' => (float) $size['height'],
        );
    } catch (Throwable $e) {
        return new WP_Error('pdf_size_exception', $e->getMessage());
    }
}

function np_order_hub_merge_pdfs($pdf_paths) {
    if (empty($pdf_paths)) {
        return new WP_Error('empty_pdfs', 'No PDFs to merge.');
    }
    $last_error = '';

    $qpdf = np_order_hub_find_binary(
        'qpdf',
        'np_order_hub_qpdf_path',
        'NP_ORDER_HUB_QPDF_PATH',
        array('/usr/bin/qpdf', '/usr/local/bin/qpdf', '/opt/homebrew/bin/qpdf')
    );
    if ($qpdf !== '') {
        $out = np_order_hub_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellarg($qpdf) . ' --empty --pages';
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $cmd .= ' -- ' . escapeshellarg($out);
            $exit = null;
            $output = '';
            $ran = np_order_hub_run_command($cmd, $exit, $output);
            if ($ran && is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (!$ran) {
                $last_error = 'Could not execute qpdf.';
            } elseif ($output !== '') {
                $last_error = 'qpdf error: ' . $output;
            } elseif ($exit !== null && $exit !== 0) {
                $last_error = 'qpdf exited with code ' . $exit . '.';
            } else {
                $last_error = 'qpdf did not create output.';
            }
            if (is_file($out)) {
                @unlink($out);
            }
        } else {
            $last_error = 'Could not create temp file for qpdf.';
        }
    }

    $gs = np_order_hub_find_binary(
        'gs',
        'np_order_hub_gs_path',
        'NP_ORDER_HUB_GS_PATH',
        array('/usr/bin/gs', '/usr/local/bin/gs', '/opt/homebrew/bin/gs')
    );
    if ($gs !== '') {
        $out = np_order_hub_tempnam('packing-slips-merge');
        if ($out) {
            $out .= '.pdf';
            $cmd = escapeshellarg($gs) . ' -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=' . escapeshellarg($out);
            foreach ($pdf_paths as $path) {
                $cmd .= ' ' . escapeshellarg($path);
            }
            $exit = null;
            $output = '';
            $ran = np_order_hub_run_command($cmd, $exit, $output);
            if ($ran && is_file($out) && filesize($out) > 1000) {
                return $out;
            }
            if (!$ran && $last_error === '') {
                $last_error = 'Could not execute ghostscript.';
            } elseif ($output !== '' && $last_error === '') {
                $last_error = 'ghostscript error: ' . $output;
            } elseif ($exit !== null && $exit !== 0 && $last_error === '') {
                $last_error = 'ghostscript exited with code ' . $exit . '.';
            } elseif ($last_error === '') {
                $last_error = 'ghostscript did not create output.';
            }
            if (is_file($out)) {
                @unlink($out);
            }
        } elseif ($last_error === '') {
            $last_error = 'Could not create temp file for ghostscript.';
        }
    }

    if ($last_error !== '') {
        $fpdi = np_order_hub_merge_pdfs_fpdi($pdf_paths);
        if (!is_wp_error($fpdi)) {
            return $fpdi;
        }
        return new WP_Error('merge_unavailable', $last_error . ' ' . $fpdi->get_error_message());
    }
    $fpdi = np_order_hub_merge_pdfs_fpdi($pdf_paths);
    if (!is_wp_error($fpdi)) {
        return $fpdi;
    }
    return new WP_Error('merge_unavailable', $fpdi->get_error_message());
}

function np_order_hub_build_packing_slips_bundle($groups) {
    if (empty($groups) || !is_array($groups)) {
        return new WP_Error('missing_groups', 'No stores selected.');
    }
    $timestamp = gmdate('Ymd-His');
    $pdf_files = array();
    $used_names = array();
    $preview_links = array();
    $errors = array();

    foreach ($groups as $store_key => $group) {
        $store_key = sanitize_key((string) $store_key);
        $store = isset($group['store']) && is_array($group['store']) ? $group['store'] : null;
        $order_ids = isset($group['order_ids']) && is_array($group['order_ids']) ? $group['order_ids'] : array();
        $order_ids = array_values(array_filter(array_map('absint', $order_ids), function ($value) {
            return $value > 0;
        }));
        if ($store_key === '' || !$store || empty($order_ids)) {
            continue;
        }
        $bulk_url = np_order_hub_build_packing_slips_url($store, $order_ids);
        if ($bulk_url === '') {
            $errors[] = 'Packing slip bulk URL is not configured for store ' . ($store['name'] ?? $store_key) . '.';
            continue;
        }
        $preview_links[] = array(
            'label' => isset($store['name']) && is_string($store['name']) && $store['name'] !== '' ? $store['name'] : $store_key,
            'url' => $bulk_url,
            'count' => count($order_ids),
        );
        $pdf_bytes = np_order_hub_fetch_packing_slips_pdf($bulk_url);
        if (is_wp_error($pdf_bytes)) {
            $errors[] = 'Packing slips failed for store ' . ($store['name'] ?? $store_key) . ': ' . $pdf_bytes->get_error_message();
            continue;
        }
        $tmp = np_order_hub_tempnam('packing-slips-' . $store_key);
        if (!$tmp) {
            $errors[] = 'Could not create temporary file for store ' . ($store['name'] ?? $store_key) . '.';
            continue;
        }
        $path = $tmp . '.pdf';
        @rename($tmp, $path);
        file_put_contents($path, $pdf_bytes);

        $label = isset($store['name']) && is_string($store['name']) && $store['name'] !== '' ? $store['name'] : $store_key;
        $label = sanitize_file_name($label);
        if ($label === '') {
            $label = $store_key !== '' ? $store_key : 'store';
        }
        $base_name = 'packing-slips-' . $label;
        $final_name = $base_name;
        $suffix = 2;
        while (isset($used_names[$final_name])) {
            $final_name = $base_name . '-' . $suffix;
            $suffix++;
        }
        $used_names[$final_name] = true;

        $pdf_files[] = array(
            'path' => $path,
            'name' => $final_name . '.pdf',
        );
    }

    if (!empty($errors)) {
        foreach ($pdf_files as $file) {
            if (!empty($file['path']) && is_file($file['path'])) {
                @unlink($file['path']);
            }
        }
        return new WP_Error('packing_slips_failed', implode(' ', $errors));
    }

    if (empty($pdf_files)) {
        return new WP_Error('packing_slips_empty', 'No packing slips could be generated.');
    }

    $pdf_paths = array_map(function ($file) {
        return $file['path'];
    }, $pdf_files);

    if (count($pdf_paths) > 1) {
        $merged = np_order_hub_merge_pdfs($pdf_paths);
        foreach ($pdf_paths as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
        if (!is_wp_error($merged)) {
            return array(
                'path' => $merged,
                'filename' => 'packing-slips-' . $timestamp . '.pdf',
                'content_type' => 'application/pdf',
                'inline' => true,
            );
        }
        return array(
            'preview_links' => $preview_links,
            'merge_error' => $merged instanceof WP_Error ? $merged->get_error_message() : '',
        );
    }

    return array(
        'path' => $pdf_paths[0],
        'filename' => 'packing-slips-' . $timestamp . '.pdf',
        'content_type' => 'application/pdf',
        'inline' => true,
    );
}

function np_order_hub_send_download($payload) {
    if (!is_array($payload) || empty($payload['path'])) {
        return;
    }
    $path = (string) $payload['path'];
    if (!is_file($path)) {
        return;
    }
    $filename = isset($payload['filename']) ? sanitize_file_name((string) $payload['filename']) : basename($path);
    if ($filename === '') {
        $filename = basename($path);
    }
    $content_type = isset($payload['content_type']) ? (string) $payload['content_type'] : 'application/octet-stream';
    $inline = !empty($payload['inline']);

    while (ob_get_level()) {
        @ob_end_clean();
    }
    nocache_headers();
    header('Content-Type: ' . $content_type);
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $filename . '"');
    if (is_file($path)) {
        $size = filesize($path);
        if ($size !== false) {
            header('Content-Length: ' . $size);
        }
    }
    readfile($path);
    @unlink($path);
    exit;
}