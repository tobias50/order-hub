<?php
function np_order_hub_set_last_pushover_result($ok, $code = '', $message = '') {
    $GLOBALS['np_order_hub_last_pushover_result'] = array(
        'ok' => !empty($ok),
        'code' => sanitize_key((string) $code),
        'message' => sanitize_text_field((string) $message),
    );
}

function np_order_hub_get_last_pushover_result() {
    $result = isset($GLOBALS['np_order_hub_last_pushover_result']) && is_array($GLOBALS['np_order_hub_last_pushover_result'])
        ? $GLOBALS['np_order_hub_last_pushover_result']
        : array();

    return wp_parse_args($result, array(
        'ok' => false,
        'code' => '',
        'message' => '',
    ));
}

function np_order_hub_log($message, $context = array()) {
    if (!is_array($context)) {
        $context = array('value' => $context);
    }

    $json = wp_json_encode($context);
    $line = (string) $message;
    if (is_string($json) && $json !== '') {
        $line .= ' ' . $json;
    }

    if (function_exists('wc_get_logger')) {
        $logger = wc_get_logger();
        $logger->info($line, array('source' => 'np-order-hub'));
        return;
    }

    error_log('[np-order-hub] ' . $line);
}

function np_order_hub_send_pushover_message($title, $message, $context = array()) {
    if (!is_array($context)) {
        $context = array('value' => $context);
    }

    np_order_hub_set_last_pushover_result(false, '', '');

    $settings = np_order_hub_get_pushover_settings();
    if (empty($settings['enabled']) || $settings['user'] === '' || $settings['token'] === '') {
        np_order_hub_log('pushover_skipped_missing_config', $context);
        np_order_hub_set_last_pushover_result(false, 'missing_config', 'Missing Pushover config.');
        return false;
    }

    $attachment_info = null;
    if (!empty($settings['logo_enabled']) && $settings['logo_url'] !== '') {
        $attachment_info = np_order_hub_pushover_prepare_attachment($settings['logo_url']);
    }
    $attachment_info = is_array($attachment_info) ? $attachment_info : array('attachment' => null, 'tmp_file' => '', 'cleanup' => false);
    $attachment = $attachment_info['attachment'];
    $tmp_file = $attachment_info['tmp_file'];
    $cleanup = !empty($attachment_info['cleanup']);

    $body = array(
        'token' => $settings['token'],
        'user' => $settings['user'],
        'title' => $title,
        'message' => $message,
    );
    if ($attachment) {
        $body['attachment'] = $attachment;
    }

    $response = wp_remote_post('https://api.pushover.net/1/messages.json', array(
        'timeout' => 15,
        'body' => $body,
    ));

    if ($cleanup && $tmp_file !== '' && file_exists($tmp_file)) {
        @unlink($tmp_file);
    }

    if (is_wp_error($response)) {
        np_order_hub_log('pushover_failed_http', array_merge($context, array(
            'error' => $response->get_error_message(),
        )));
        np_order_hub_set_last_pushover_result(false, 'http_error', $response->get_error_message());
        return false;
    }

    $code = (int) wp_remote_retrieve_response_code($response);
    $response_body = (string) wp_remote_retrieve_body($response);
    $decoded = $response_body !== '' ? json_decode($response_body, true) : null;
    $api_status = is_array($decoded) && isset($decoded['status']) ? (int) $decoded['status'] : 0;

    if ($code < 200 || $code >= 300 || $api_status !== 1) {
        $error_message = '';
        if (is_array($decoded) && !empty($decoded['errors']) && is_array($decoded['errors'])) {
            $error_message = implode('; ', array_map('strval', $decoded['errors']));
        }
        if ($error_message === '') {
            $error_message = is_array($decoded) ? wp_json_encode($decoded) : substr($response_body, 0, 500);
        }
        np_order_hub_log('pushover_failed_response', array_merge($context, array(
            'http_code' => $code,
            'api_status' => $api_status,
            'response' => is_array($decoded) ? $decoded : substr($response_body, 0, 500),
        )));
        np_order_hub_set_last_pushover_result(false, 'api_response', $error_message);
        return false;
    }

    np_order_hub_log('pushover_sent', array_merge($context, array(
        'http_code' => $code,
        'request_id' => is_array($decoded) && !empty($decoded['request']) ? (string) $decoded['request'] : '',
    )));
    np_order_hub_set_last_pushover_result(
        true,
        'sent',
        is_array($decoded) && !empty($decoded['request']) ? (string) $decoded['request'] : ''
    );

    return true;
}

function np_order_hub_get_help_scout_settings() {
    $status = sanitize_key((string) get_option(NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION, 'pending'));
    if (!in_array($status, array('active', 'pending', 'closed'), true)) {
        $status = 'pending';
    }
    return array(
        'token' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, '')),
        'mailbox_id' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION, 0),
        'default_status' => $status,
        'user_id' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_USER_OPTION, 0),
        'client_id' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION, '')),
        'client_secret' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION, '')),
        'refresh_token' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, '')),
        'expires_at' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0),
        'webhook_secret' => trim((string) get_option(NP_ORDER_HUB_HELP_SCOUT_WEBHOOK_SECRET_OPTION, '')),
        'auto_lookup' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_AUTO_LOOKUP_OPTION, 1),
        'local_inbox' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_LOCAL_INBOX_OPTION, 1),
        'close_imported' => (int) get_option(NP_ORDER_HUB_HELP_SCOUT_CLOSE_IMPORTED_OPTION, 1),
    );
}

function np_order_hub_help_scout_get_webhook_url() {
    return rest_url('np-order-hub/v1/help-scout-webhook');
}

function np_order_hub_help_scout_normalize_name($value) {
    $value = sanitize_text_field((string) $value);
    if ($value === '') {
        return '';
    }
    $value = strtolower($value);
    $value = preg_replace('/\s+/', ' ', trim($value));
    return is_string($value) ? $value : '';
}

function np_order_hub_help_scout_sanitize_email($value) {
    $email = sanitize_email((string) $value);
    return strtolower(trim($email));
}

function np_order_hub_help_scout_verify_webhook_signature($body, $signature, $secret) {
    $body = (string) $body;
    $signature = trim((string) $signature);
    $secret = trim((string) $secret);
    if ($signature === '' || $secret === '') {
        return false;
    }

    if (stripos($signature, 'sha1=') === 0) {
        $signature = substr($signature, 5);
    }

    $expected_base64 = base64_encode(hash_hmac('sha1', $body, $secret, true));
    if (hash_equals($expected_base64, $signature)) {
        return true;
    }

    if (preg_match('/^[A-Fa-f0-9]{40}$/', $signature)) {
        $expected_hex = hash_hmac('sha1', $body, $secret);
        return hash_equals($expected_hex, strtolower($signature));
    }

    return false;
}

function np_order_hub_help_scout_should_process_webhook_event($event, $payload = array()) {
    $event = strtolower(trim((string) $event));
    if ($event === '' && is_array($payload) && !empty($payload['event'])) {
        $event = strtolower(trim((string) $payload['event']));
    }

    $allowed = array(
        'convo.created',
        'convo.customer.created',
        'convo.customer.reply.created',
        'conversation.created',
        'conversation.customer.created',
        'conversation.customer.reply.created',
    );

    return in_array($event, $allowed, true);
}

function np_order_hub_help_scout_extract_conversation_id($payload) {
    if (!is_array($payload)) {
        return 0;
    }

    $candidates = array(
        $payload['id'] ?? 0,
        $payload['conversation']['id'] ?? 0,
        $payload['data']['id'] ?? 0,
        $payload['data']['conversation']['id'] ?? 0,
        $payload['object']['id'] ?? 0,
    );
    foreach ($candidates as $candidate) {
        $conversation_id = absint($candidate);
        if ($conversation_id > 0) {
            return $conversation_id;
        }
    }

    return 0;
}

function np_order_hub_help_scout_extract_customer($conversation, $payload = array()) {
    $email_candidates = array();
    $first_candidates = array();
    $last_candidates = array();
    $full_candidates = array();

    $sources = array($conversation, is_array($payload) ? $payload : array());
    foreach ($sources as $source) {
        if (!is_array($source)) {
            continue;
        }
        $email_candidates[] = $source['primaryCustomer']['email'] ?? '';
        $email_candidates[] = $source['customer']['email'] ?? '';
        $email_candidates[] = $source['createdBy']['email'] ?? '';
        $email_candidates[] = $source['_embedded']['primaryCustomer']['email'] ?? '';
        $email_candidates[] = $source['_embedded']['customer']['email'] ?? '';
        $email_candidates[] = $source['fromEmail'] ?? '';

        $first_candidates[] = $source['primaryCustomer']['first'] ?? '';
        $first_candidates[] = $source['primaryCustomer']['firstName'] ?? '';
        $first_candidates[] = $source['customer']['first'] ?? '';
        $first_candidates[] = $source['customer']['firstName'] ?? '';
        $first_candidates[] = $source['_embedded']['primaryCustomer']['first'] ?? '';
        $first_candidates[] = $source['_embedded']['primaryCustomer']['firstName'] ?? '';
        $first_candidates[] = $source['_embedded']['customer']['first'] ?? '';
        $first_candidates[] = $source['_embedded']['customer']['firstName'] ?? '';
        $first_candidates[] = $source['createdBy']['firstName'] ?? '';

        $last_candidates[] = $source['primaryCustomer']['last'] ?? '';
        $last_candidates[] = $source['primaryCustomer']['lastName'] ?? '';
        $last_candidates[] = $source['customer']['last'] ?? '';
        $last_candidates[] = $source['customer']['lastName'] ?? '';
        $last_candidates[] = $source['_embedded']['primaryCustomer']['last'] ?? '';
        $last_candidates[] = $source['_embedded']['primaryCustomer']['lastName'] ?? '';
        $last_candidates[] = $source['_embedded']['customer']['last'] ?? '';
        $last_candidates[] = $source['_embedded']['customer']['lastName'] ?? '';
        $last_candidates[] = $source['createdBy']['lastName'] ?? '';

        $full_candidates[] = $source['primaryCustomer']['name'] ?? '';
        $full_candidates[] = $source['customer']['name'] ?? '';
        $full_candidates[] = $source['_embedded']['primaryCustomer']['name'] ?? '';
        $full_candidates[] = $source['_embedded']['customer']['name'] ?? '';
    }

    $email = '';
    foreach ($email_candidates as $candidate) {
        $candidate = np_order_hub_help_scout_sanitize_email($candidate);
        if ($candidate !== '') {
            $email = $candidate;
            break;
        }
    }

    $first = '';
    foreach ($first_candidates as $candidate) {
        $candidate = np_order_hub_help_scout_normalize_name($candidate);
        if ($candidate !== '') {
            $first = $candidate;
            break;
        }
    }

    $last = '';
    foreach ($last_candidates as $candidate) {
        $candidate = np_order_hub_help_scout_normalize_name($candidate);
        if ($candidate !== '') {
            $last = $candidate;
            break;
        }
    }

    $full_name = '';
    foreach ($full_candidates as $candidate) {
        $candidate = np_order_hub_help_scout_normalize_name($candidate);
        if ($candidate !== '') {
            $full_name = $candidate;
            break;
        }
    }

    if ($full_name === '' && ($first !== '' || $last !== '')) {
        $full_name = trim($first . ' ' . $last);
    }

    if (($first === '' || $last === '') && $full_name !== '' && strpos($full_name, ' ') !== false) {
        $parts = explode(' ', $full_name);
        if ($first === '') {
            $first = np_order_hub_help_scout_normalize_name(array_shift($parts));
        }
        if ($last === '') {
            $last = np_order_hub_help_scout_normalize_name(implode(' ', $parts));
        }
    }

    return array(
        'email' => $email,
        'first_name' => $first,
        'last_name' => $last,
        'full_name' => $full_name,
    );
}

function np_order_hub_help_scout_record_matches_customer($record, $customer) {
    if (!is_array($record) || empty($record['payload'])) {
        return false;
    }

    $payload = json_decode((string) $record['payload'], true);
    if (!is_array($payload)) {
        return false;
    }

    $customer_email = isset($customer['email']) ? (string) $customer['email'] : '';
    $customer_first = isset($customer['first_name']) ? (string) $customer['first_name'] : '';
    $customer_last = isset($customer['last_name']) ? (string) $customer['last_name'] : '';
    $customer_full = isset($customer['full_name']) ? (string) $customer['full_name'] : '';

    $profiles = array();
    if (!empty($payload['billing']) && is_array($payload['billing'])) {
        $profiles[] = $payload['billing'];
    }
    if (!empty($payload['shipping']) && is_array($payload['shipping'])) {
        $profiles[] = $payload['shipping'];
    }
    if (empty($profiles)) {
        return false;
    }

    foreach ($profiles as $profile) {
        $profile_email = np_order_hub_help_scout_sanitize_email($profile['email'] ?? '');
        $profile_first = np_order_hub_help_scout_normalize_name($profile['first_name'] ?? '');
        $profile_last = np_order_hub_help_scout_normalize_name($profile['last_name'] ?? '');
        $profile_full = np_order_hub_help_scout_normalize_name(trim($profile_first . ' ' . $profile_last));
        $profile_company = np_order_hub_help_scout_normalize_name($profile['company'] ?? '');

        if ($customer_email !== '' && $profile_email !== '' && $customer_email === $profile_email) {
            return true;
        }

        if ($customer_first !== '' && $customer_last !== '' && $profile_first !== '' && $profile_last !== '') {
            if ($customer_first === $profile_first && $customer_last === $profile_last) {
                return true;
            }
        }

        if ($customer_full !== '' && ($profile_full !== '' || $profile_company !== '')) {
            if ($customer_full === $profile_full || $customer_full === $profile_company) {
                return true;
            }
        }

        if ($customer_first !== '' && $customer_last === '' && $profile_first !== '' && $customer_first === $profile_first) {
            return true;
        }
    }

    return false;
}
