<?php
function np_order_hub_help_scout_find_matching_orders($customer, $limit = 8) {
    global $wpdb;
    $table = np_order_hub_table_name();

    $email = isset($customer['email']) ? (string) $customer['email'] : '';
    $first = isset($customer['first_name']) ? (string) $customer['first_name'] : '';
    $last = isset($customer['last_name']) ? (string) $customer['last_name'] : '';
    $full = isset($customer['full_name']) ? (string) $customer['full_name'] : '';

    $clauses = array();
    $args = array();

    if ($email !== '') {
        $clauses[] = 'payload LIKE %s';
        $args[] = '%' . $wpdb->esc_like($email) . '%';
    }
    if ($first !== '' && $last !== '') {
        $clauses[] = '(payload LIKE %s AND payload LIKE %s)';
        $args[] = '%' . $wpdb->esc_like($first) . '%';
        $args[] = '%' . $wpdb->esc_like($last) . '%';
    } elseif ($full !== '') {
        $clauses[] = 'payload LIKE %s';
        $args[] = '%' . $wpdb->esc_like($full) . '%';
    } elseif ($first !== '') {
        $clauses[] = 'payload LIKE %s';
        $args[] = '%' . $wpdb->esc_like($first) . '%';
    }

    if (empty($clauses)) {
        return array();
    }

    $candidate_limit = max((int) $limit * 6, 25);
    $candidate_limit = min($candidate_limit, 120);
    $where = '(' . implode(' OR ', $clauses) . ')';
    $sql = "SELECT * FROM $table WHERE $where ORDER BY date_created_gmt DESC, id DESC LIMIT %d";
    $query_args = array_merge($args, array($candidate_limit));
    $candidates = $wpdb->get_results($wpdb->prepare($sql, $query_args), ARRAY_A);
    if (!is_array($candidates) || empty($candidates)) {
        return array();
    }

    $matches = array();
    foreach ($candidates as $candidate) {
        if (!np_order_hub_help_scout_record_matches_customer($candidate, $customer)) {
            continue;
        }
        $matches[] = $candidate;
        if (count($matches) >= $limit) {
            break;
        }
    }

    return $matches;
}

function np_order_hub_help_scout_build_match_note($customer, $matches) {
    $lines = array();
    $lines[] = 'Automatisk oppslag fra Order Hub';

    $customer_text = '';
    $full_name = isset($customer['full_name']) ? trim((string) $customer['full_name']) : '';
    $email = isset($customer['email']) ? trim((string) $customer['email']) : '';
    if ($full_name !== '' && $email !== '') {
        $customer_text = $full_name . ' <' . $email . '>';
    } elseif ($full_name !== '') {
        $customer_text = $full_name;
    } elseif ($email !== '') {
        $customer_text = $email;
    }
    if ($customer_text !== '') {
        $lines[] = 'Kunde: ' . $customer_text;
    }

    $lines[] = 'Fant ' . count($matches) . ' matchende ordre:';
    $lines[] = '';

    foreach ($matches as $match) {
        if (!is_array($match)) {
            continue;
        }
        $order_id = isset($match['order_id']) ? (int) $match['order_id'] : 0;
        $order_number = isset($match['order_number']) ? (string) $match['order_number'] : '';
        $label = $order_number !== '' ? ('#' . $order_number) : ('#' . $order_id);
        $store_name = isset($match['store_name']) ? sanitize_text_field((string) $match['store_name']) : 'Store';
        $status = isset($match['status']) ? ucwords(str_replace('-', ' ', sanitize_key((string) $match['status']))) : '';
        $date = '';
        if (!empty($match['date_created_gmt']) && $match['date_created_gmt'] !== '0000-00-00 00:00:00') {
            $date = get_date_from_gmt((string) $match['date_created_gmt'], 'd.m.Y');
        }
        $total = np_order_hub_format_money(
            isset($match['total']) ? (float) $match['total'] : 0.0,
            isset($match['currency']) ? (string) $match['currency'] : ''
        );
        $parts = array($label, $store_name);
        if ($status !== '') {
            $parts[] = $status;
        }
        if ($date !== '') {
            $parts[] = $date;
        }
        $parts[] = $total;
        $lines[] = '- ' . implode(' | ', $parts);
        $lines[] = '  Hub: ' . admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $match['id']);
        if (!empty($match['order_admin_url'])) {
            $lines[] = '  Butikk: ' . (string) $match['order_admin_url'];
        }
        $lines[] = '';
    }

    return trim(implode("\n", $lines));
}

function np_order_hub_help_scout_add_note($settings, $conversation_id, $message) {
    $conversation_id = (int) $conversation_id;
    $message = trim((string) $message);
    if ($conversation_id < 1 || $message === '') {
        return new WP_Error('help_scout_note_invalid', 'Conversation ID and message are required.');
    }

    $payload = array(
        'text' => $message,
        'type' => 'note',
    );

    return np_order_hub_help_scout_request(
        $settings,
        'POST',
        'conversations/' . $conversation_id . '/notes',
        $payload
    );
}

function np_order_hub_handle_help_scout_webhook(WP_REST_Request $request) {
    $settings = np_order_hub_get_help_scout_settings();
    if (empty($settings['auto_lookup'])) {
        return new WP_REST_Response(array('status' => 'disabled'), 200);
    }

    $secret = isset($settings['webhook_secret']) ? trim((string) $settings['webhook_secret']) : '';
    if ($secret === '') {
        return new WP_REST_Response(array('error' => 'missing_webhook_secret'), 401);
    }

    $body = (string) $request->get_body();
    $signature = trim((string) $request->get_header('X-HelpScout-Signature'));
    if (!np_order_hub_help_scout_verify_webhook_signature($body, $signature, $secret)) {
        error_log('[np-order-hub] help_scout_bad_signature');
        return new WP_REST_Response(array('error' => 'bad_signature'), 401);
    }

    $payload = json_decode($body, true);
    if (!is_array($payload)) {
        return new WP_REST_Response(array('error' => 'bad_payload'), 400);
    }

    $event = strtolower(trim((string) $request->get_header('X-HelpScout-Event')));
    if (!np_order_hub_help_scout_should_process_webhook_event($event, $payload)) {
        return new WP_REST_Response(array('status' => 'ignored_event'), 200);
    }

    $event_hash = 'np_order_hub_hs_' . substr(hash('sha256', $event . '|' . $signature . '|' . $body), 0, 40);
    if (get_transient($event_hash)) {
        return new WP_REST_Response(array('status' => 'duplicate'), 200);
    }
    set_transient($event_hash, 1, 10 * MINUTE_IN_SECONDS);

    $conversation_id = np_order_hub_help_scout_extract_conversation_id($payload);
    if ($conversation_id < 1) {
        return new WP_REST_Response(array('status' => 'missing_conversation_id'), 200);
    }

    $payload_mailbox_id = isset($payload['mailboxId']) ? absint($payload['mailboxId']) : 0;
    if (!empty($settings['mailbox_id']) && $payload_mailbox_id > 0 && $payload_mailbox_id !== (int) $settings['mailbox_id']) {
        return new WP_REST_Response(array('status' => 'mailbox_mismatch'), 200);
    }

    $conversation = np_order_hub_help_scout_get_conversation($settings, $conversation_id);
    if (is_wp_error($conversation)) {
        error_log('[np-order-hub] help_scout_fetch_conversation_failed ' . wp_json_encode(array(
            'conversation_id' => $conversation_id,
            'message' => $conversation->get_error_message(),
        )));
        return new WP_REST_Response(array('status' => 'fetch_failed'), 200);
    }

    $conversation_mailbox_id = isset($conversation['mailboxId']) ? absint($conversation['mailboxId']) : 0;
    if (!empty($settings['mailbox_id']) && $conversation_mailbox_id > 0 && $conversation_mailbox_id !== (int) $settings['mailbox_id']) {
        return new WP_REST_Response(array('status' => 'mailbox_mismatch'), 200);
    }

    $customer = np_order_hub_help_scout_extract_customer($conversation, $payload);
    if (empty($customer['email']) && empty($customer['full_name']) && empty($customer['first_name'])) {
        return new WP_REST_Response(array('status' => 'missing_customer'), 200);
    }

    $matches = np_order_hub_help_scout_find_matching_orders($customer, 8);
    if (empty($matches)) {
        return new WP_REST_Response(array('status' => 'no_matches'), 200);
    }

    $note = np_order_hub_help_scout_build_match_note($customer, $matches);
    $response = np_order_hub_help_scout_add_note($settings, $conversation_id, $note);
    if (is_wp_error($response)) {
        error_log('[np-order-hub] help_scout_note_failed ' . wp_json_encode(array(
            'conversation_id' => $conversation_id,
            'message' => $response->get_error_message(),
        )));
        return new WP_REST_Response(array('status' => 'note_failed', 'matches' => count($matches)), 200);
    }

    return new WP_REST_Response(array(
        'status' => 'matched',
        'conversation_id' => $conversation_id,
        'matches' => count($matches),
    ), 200);
}

function np_order_hub_help_scout_get_redirect_url() {
    return admin_url('admin.php?page=np-order-hub-help-scout');
}

function np_order_hub_redirect_with_fallback($url) {
    $url = trim((string) $url);
    if ($url === '') {
        return;
    }

    if (!headers_sent()) {
        $target_host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
        $site_host = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
        if ($target_host !== '' && $site_host !== '' && $target_host !== $site_host) {
            wp_redirect($url);
        } else {
            wp_safe_redirect($url);
        }
        exit;
    }

    $json_url = wp_json_encode($url);
    if ($json_url === false) {
        $json_url = '"' . esc_js($url) . '"';
    }
    echo '<script>window.location.href=' . $json_url . ';</script>';
    echo '<noscript><meta http-equiv="refresh" content="0;url=' . esc_url($url) . '" /></noscript>';
    echo '<p>Redirecting... <a href="' . esc_url($url) . '">Continue</a></p>';
    exit;
}

function np_order_hub_help_scout_store_tokens($token_data, $fallback_refresh = '') {
    $access_token = isset($token_data['access_token']) ? trim((string) $token_data['access_token']) : '';
    if ($access_token !== '') {
        update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, $access_token);
    }

    $refresh_token = isset($token_data['refresh_token']) ? trim((string) $token_data['refresh_token']) : '';
    if ($refresh_token === '' && $fallback_refresh !== '') {
        $refresh_token = $fallback_refresh;
    }
    if ($refresh_token !== '') {
        update_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, $refresh_token);
    }

    $expires_in = isset($token_data['expires_in']) ? (int) $token_data['expires_in'] : 0;
    if ($expires_in > 0) {
        update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, time() + $expires_in - 60);
    } else {
        update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0);
    }
}