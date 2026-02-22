<?php
function np_order_hub_extract_packing_slip_url($payload) {
    if (!is_array($payload)) {
        return '';
    }
    if (empty($payload['np_wpo_packing_slip_url'])) {
        return '';
    }
    $url = esc_url_raw((string) $payload['np_wpo_packing_slip_url']);
    return $url;
}

function np_order_hub_extract_access_key($payload) {
    if (!is_array($payload)) {
        return '';
    }
    if (!empty($payload['np_wpo_packing_slip_url'])) {
        $parsed = wp_parse_url((string) $payload['np_wpo_packing_slip_url']);
        if (!empty($parsed['query'])) {
            parse_str($parsed['query'], $params);
            if (!empty($params['access_key'])) {
                return sanitize_text_field((string) $params['access_key']);
            }
        }
    }
    $candidates = array(
        'np_wpo_access_key',
        'wpo_wcpdf_access_key',
        'wcpdf_access_key',
        'access_key',
    );
    foreach ($candidates as $key) {
        if (!empty($payload[$key])) {
            return sanitize_text_field((string) $payload[$key]);
        }
    }
    if (!empty($payload['meta_data']) && is_array($payload['meta_data'])) {
        foreach ($payload['meta_data'] as $meta) {
            if (!is_array($meta) || empty($meta['key'])) {
                continue;
            }
            $meta_key = sanitize_key((string) $meta['key']);
            if (in_array($meta_key, array('np_wpo_access_key', 'wpo_wcpdf_access_key', 'wcpdf_access_key'), true)) {
                if (isset($meta['value'])) {
                    return sanitize_text_field((string) $meta['value']);
                }
            }
        }
    }
    return '';
}

function np_order_hub_pdf_bytes_look_valid($bytes) {
    if (!is_string($bytes) || $bytes === '') {
        return false;
    }
    $pos = strpos($bytes, '%PDF-');
    if ($pos === false) {
        return false;
    }
    return $pos < 1024;
}

function np_order_hub_fetch_packing_slips_pdf($url) {
    return np_order_hub_fetch_pdf_document($url, 'Packing slip');
}

function np_order_hub_is_exec_function_enabled($name) {
    if (!is_string($name) || $name === '') {
        return false;
    }
    if (!function_exists($name)) {
        return false;
    }
    $disabled = ini_get('disable_functions');
    if (is_string($disabled) && $disabled !== '') {
        $disabled_list = array_map('trim', explode(',', $disabled));
        if (in_array($name, $disabled_list, true)) {
            return false;
        }
    }
    return is_callable($name);
}

function np_order_hub_run_command($cmd, &$exit_code = null, &$output = '') {
    $exit_code = null;
    $output = '';
    if (!is_string($cmd) || $cmd === '') {
        return false;
    }

    if (np_order_hub_is_exec_function_enabled('proc_open')) {
        $descriptors = array(
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($process)) {
            $stdout = isset($pipes[1]) ? stream_get_contents($pipes[1]) : '';
            $stderr = isset($pipes[2]) ? stream_get_contents($pipes[2]) : '';
            if (isset($pipes[1]) && is_resource($pipes[1])) {
                fclose($pipes[1]);
            }
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                fclose($pipes[2]);
            }
            $exit_code = proc_close($process);
            $output = trim($stdout . "\n" . $stderr);
            return true;
        }
    }

    if (np_order_hub_is_exec_function_enabled('exec')) {
        $lines = array();
        $code = 0;
        @exec($cmd . ' 2>&1', $lines, $code);
        $exit_code = $code;
        $output = trim(implode("\n", $lines));
        return true;
    }

    if (np_order_hub_is_exec_function_enabled('shell_exec')) {
        $output = trim((string) @shell_exec($cmd . ' 2>&1'));
        $exit_code = null;
        return true;
    }

    return false;
}

function np_order_hub_find_binary($name, $filter_name, $env_name, $candidates = array()) {
    $path = apply_filters($filter_name, '');
    if (is_string($path) && $path !== '' && is_file($path)) {
        return $path;
    }
    if (is_string($env_name) && $env_name !== '') {
        $env = getenv($env_name);
        if (is_string($env) && $env !== '' && is_file($env)) {
            return $env;
        }
    }
    if (np_order_hub_is_exec_function_enabled('shell_exec')) {
        $cmd = 'command -v ' . escapeshellarg($name);
        $found = trim((string) @shell_exec($cmd . ' 2>/dev/null'));
        if ($found !== '' && is_file($found)) {
            return $found;
        }
    }
    foreach ($candidates as $candidate) {
        if (is_string($candidate) && $candidate !== '' && is_file($candidate)) {
            return $candidate;
        }
    }
    return '';
}

function np_order_hub_require_fpdi() {
    if (class_exists('\\setasign\\Fpdi\\Fpdi')) {
        return true;
    }
        $np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;
    $base = dirname($np_order_hub_main_file) . '/vendor/setasign';
    $fpdf = $base . '/fpdf/fpdf.php';
    if (is_file($fpdf) && !class_exists('FPDF')) {
        require_once $fpdf;
    }
    $fpdi_base = $base . '/fpdi/src/';
    if (!is_dir($fpdi_base)) {
        return false;
    }
    static $registered = false;
    if (!$registered) {
        $registered = true;
        $prefix = 'setasign\\Fpdi\\';
        $base_dir = $fpdi_base;
        spl_autoload_register(function ($class) use ($prefix, $base_dir) {
            if (strpos($class, $prefix) !== 0) {
                return;
            }
            $relative = substr($class, strlen($prefix));
            if ($relative === '') {
                return;
            }
            $file = $base_dir . str_replace('\\', '/', $relative) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        });
    }
    return class_exists('\\setasign\\Fpdi\\Fpdi');
}

function np_order_hub_merge_pdfs_fpdi($pdf_paths, $options = array()) {
    if (!np_order_hub_require_fpdi()) {
        return new WP_Error('fpdi_missing', 'FPDI library missing.');
    }
    if (!class_exists('\\setasign\\Fpdi\\Fpdi')) {
        return new WP_Error('fpdi_missing', 'FPDI class not available.');
    }
    $fixed_size = null;
    if (is_array($options) && isset($options['fixed_page_size']) && is_array($options['fixed_page_size'])) {
        $w = isset($options['fixed_page_size']['width']) ? (float) $options['fixed_page_size']['width'] : 0.0;
        $h = isset($options['fixed_page_size']['height']) ? (float) $options['fixed_page_size']['height'] : 0.0;
        if ($w > 0 && $h > 0) {
            $fixed_size = array(
                'width' => $w,
                'height' => $h,
            );
        }
    }
    try {
        $pdf = new \setasign\Fpdi\Fpdi();
        foreach ($pdf_paths as $path) {
            if (!is_file($path)) {
                continue;
            }
            $page_count = $pdf->setSourceFile($path);
            if (!$page_count || $page_count < 1) {
                continue;
            }
            for ($page_no = 1; $page_no <= $page_count; $page_no++) {
                $tpl_id = $pdf->importPage($page_no);
                $source_size = $pdf->getTemplateSize($tpl_id);
                if (!is_array($source_size) || empty($source_size['width']) || empty($source_size['height'])) {
                    continue;
                }
                $size = $fixed_size ? $fixed_size : array(
                    'width' => (float) $source_size['width'],
                    'height' => (float) $source_size['height'],
                );
                $orientation = ($size['width'] > $size['height']) ? 'L' : 'P';
                $pdf->AddPage($orientation, array($size['width'], $size['height']));
                if ($fixed_size) {
                    $pdf->useTemplate($tpl_id, 0, 0, $size['width'], $size['height']);
                } else {
                    $pdf->useTemplate($tpl_id);
                }
            }
        }
        $out = np_order_hub_tempnam('packing-slips-merge');
        if (!$out) {
            return new WP_Error('fpdi_temp_failed', 'Could not create temp file for FPDI merge.');
        }
        $out .= '.pdf';
        $pdf->Output('F', $out);
        if (is_file($out) && filesize($out) > 1000) {
            return $out;
        }
        if (is_file($out)) {
            @unlink($out);
        }
        return new WP_Error('fpdi_merge_failed', 'FPDI did not create output.');
    } catch (Throwable $e) {
        return new WP_Error('fpdi_exception', $e->getMessage());
    }
}