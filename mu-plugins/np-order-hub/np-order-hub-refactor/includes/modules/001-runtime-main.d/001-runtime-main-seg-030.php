<?php
function np_order_hub_get_record($record_id) {
    $record_id = absint($record_id);
    if ($record_id < 1) {
        return null;
    }

    global $wpdb;
    $table = np_order_hub_table_name();
    return $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $table WHERE id = %d", $record_id),
        ARRAY_A
    );
}

function np_order_hub_help_scout_case_status_options() {
    return array(
        'active' => 'Aktiv',
        'closed' => 'Lukket',
    );
}

function np_order_hub_help_scout_normalize_case_status($status) {
    $status = sanitize_key((string) $status);
    if ($status === 'closed') {
        return 'closed';
    }
    if (in_array($status, array('active', 'pending'), true)) {
        return 'active';
    }

    return $status !== '' ? $status : 'active';
}

function np_order_hub_help_scout_case_status_label($status) {
    $status = np_order_hub_help_scout_normalize_case_status($status);
    $options = np_order_hub_help_scout_case_status_options();
    return isset($options[$status]) ? $options[$status] : ucfirst($status);
}

function np_order_hub_help_scout_case_thread_type_label($thread_type) {
    $thread_type = sanitize_key((string) $thread_type);
    $labels = array(
        'customer' => 'Kunde',
        'reply' => 'Svar',
        'note' => 'Intern note',
        'lineitem' => 'Line item',
        'forward' => 'Forward',
    );
    return isset($labels[$thread_type]) ? $labels[$thread_type] : ucfirst(str_replace('-', ' ', $thread_type));
}

function np_order_hub_help_scout_case_web_url($conversation) {
    if (!is_array($conversation)) {
        return '';
    }

    $candidates = array(
        $conversation['webUrl'] ?? '',
        $conversation['webLocation'] ?? '',
        $conversation['_links']['web']['href'] ?? '',
    );
    foreach ($candidates as $candidate) {
        $candidate = trim((string) $candidate);
        if ($candidate !== '') {
            return $candidate;
        }
    }

    $conversation_id = isset($conversation['id']) ? absint($conversation['id']) : 0;
    $conversation_number = isset($conversation['number']) ? absint($conversation['number']) : 0;
    if ($conversation_id > 0 && $conversation_number > 0) {
        return 'https://secure.helpscout.net/conversation/' . $conversation_id . '/' . $conversation_number . '/';
    }

    return '';
}

function np_order_hub_help_scout_get_conversation_with_threads($settings, $conversation_id) {
    $response = np_order_hub_help_scout_request(
        $settings,
        'GET',
        'conversations/' . (int) $conversation_id . '?embed=threads'
    );
    if (is_wp_error($response)) {
        return $response;
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded)) {
        return new WP_Error('help_scout_bad_response', 'Help Scout conversation response missing JSON.');
    }

    if (empty($decoded['_embedded']['threads'])) {
        $threads_url = isset($decoded['_links']['threads']['href']) ? trim((string) $decoded['_links']['threads']['href']) : '';
        if ($threads_url !== '') {
            $threads = np_order_hub_help_scout_get_threads_by_url($settings, $threads_url);
            if (!is_wp_error($threads)) {
                $decoded['_embedded']['threads'] = $threads;
            }
        }
    }

    return $decoded;
}

function np_order_hub_help_scout_get_threads_by_url($settings, $threads_url) {
    $threads_url = trim((string) $threads_url);
    if ($threads_url === '') {
        return new WP_Error('help_scout_missing_threads_url', 'Help Scout threads URL missing.');
    }

    $prefix = 'https://api.helpscout.net/v2/';
    if (strpos($threads_url, $prefix) === 0) {
        $threads_url = substr($threads_url, strlen($prefix));
    }
    $threads_url = ltrim($threads_url, '/');

    $response = np_order_hub_help_scout_request($settings, 'GET', $threads_url);
    if (is_wp_error($response)) {
        return $response;
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded)) {
        return new WP_Error('help_scout_bad_threads_response', 'Help Scout threads response missing JSON.');
    }

    if (!empty($decoded['_embedded']['threads']) && is_array($decoded['_embedded']['threads'])) {
        return $decoded['_embedded']['threads'];
    }
    if (!empty($decoded['threads']) && is_array($decoded['threads'])) {
        return $decoded['threads'];
    }

    return array();
}

function np_order_hub_help_scout_extract_threads($conversation) {
    if (!is_array($conversation)) {
        return array();
    }

    if (!empty($conversation['_embedded']['threads']) && is_array($conversation['_embedded']['threads'])) {
        return $conversation['_embedded']['threads'];
    }
    if (!empty($conversation['threads']) && is_array($conversation['threads'])) {
        return $conversation['threads'];
    }

    return array();
}

function np_order_hub_help_scout_extract_thread_body($thread) {
    if (!is_array($thread)) {
        return '';
    }

    $candidates = array(
        $thread['body'] ?? '',
        $thread['text'] ?? '',
        $thread['bodyPreview'] ?? '',
        $thread['preview'] ?? '',
    );
    foreach ($candidates as $candidate) {
        if (is_string($candidate) && trim($candidate) !== '') {
            return trim((string) $candidate);
        }
    }

    return '';
}

function np_order_hub_help_scout_extract_thread_author_email($thread) {
    if (!is_array($thread)) {
        return '';
    }

    $candidates = array(
        $thread['customer']['email'] ?? '',
        $thread['createdBy']['email'] ?? '',
        $thread['assignedTo']['email'] ?? '',
        $thread['from'] ?? '',
        $thread['createdBy']['address'] ?? '',
    );
    foreach ($candidates as $candidate) {
        $email = np_order_hub_help_scout_sanitize_email($candidate);
        if ($email !== '') {
            return $email;
        }
    }

    return '';
}

function np_order_hub_help_scout_extract_thread_author_name($thread) {
    if (!is_array($thread)) {
        return '';
    }

    $parts = array(
        trim((string) ($thread['customer']['name'] ?? '')),
        trim((string) ($thread['createdBy']['name'] ?? '')),
        trim((string) ($thread['assignedTo']['name'] ?? '')),
        trim((string) ($thread['createdBy']['firstName'] ?? '') . ' ' . (string) ($thread['createdBy']['lastName'] ?? '')),
    );
    foreach ($parts as $part) {
        $part = trim((string) $part);
        if ($part !== '') {
            return $part;
        }
    }

    return '';
}

function np_order_hub_help_scout_extract_thread_created_gmt($thread) {
    if (!is_array($thread)) {
        return null;
    }

    $candidates = array(
        $thread['createdAt'] ?? '',
        $thread['updatedAt'] ?? '',
    );
    foreach ($candidates as $candidate) {
        $candidate = trim((string) $candidate);
        if ($candidate === '') {
            continue;
        }
        $timestamp = strtotime($candidate);
        if ($timestamp !== false) {
            return gmdate('Y-m-d H:i:s', $timestamp);
        }
    }

    return null;
}

function np_order_hub_help_scout_upsert_local_case($conversation, $matches = array()) {
    np_order_hub_ensure_help_scout_case_tables();

    if (!is_array($conversation)) {
        return new WP_Error('help_scout_invalid_conversation', 'Invalid Help Scout conversation payload.');
    }

    $conversation_id = isset($conversation['id']) ? absint($conversation['id']) : 0;
    if ($conversation_id < 1) {
        return new WP_Error('help_scout_missing_conversation_id', 'Help Scout conversation ID missing.');
    }

    global $wpdb;
    $cases_table = np_order_hub_help_scout_cases_table_name();
    $messages_table = np_order_hub_help_scout_messages_table_name();
    $links_table = np_order_hub_help_scout_case_links_table_name();

    $threads = np_order_hub_help_scout_extract_threads($conversation);
    $customer = np_order_hub_help_scout_extract_customer($conversation, array());
    $web_url = np_order_hub_help_scout_case_web_url($conversation);
    $preview = trim((string) ($conversation['preview'] ?? ''));
    $remote_status = sanitize_key((string) ($conversation['status'] ?? ''));
    $is_closed_remote = np_order_hub_help_scout_normalize_case_status($remote_status) === 'closed';
    $mailbox_id = isset($conversation['mailboxId']) ? absint($conversation['mailboxId']) : 0;
    $conversation_number = isset($conversation['number']) ? absint($conversation['number']) : 0;
    $subject = sanitize_text_field((string) ($conversation['subject'] ?? ''));

    $last_thread_at = null;
    $last_customer_thread_at = null;
    foreach ($threads as $thread) {
        if (!is_array($thread)) {
            continue;
        }
        $thread_created = np_order_hub_help_scout_extract_thread_created_gmt($thread);
        if ($thread_created !== null && ($last_thread_at === null || $thread_created > $last_thread_at)) {
            $last_thread_at = $thread_created;
        }
        $thread_type = sanitize_key((string) ($thread['type'] ?? ''));
        if (in_array($thread_type, array('customer', 'message'), true) && $thread_created !== null && ($last_customer_thread_at === null || $thread_created > $last_customer_thread_at)) {
            $last_customer_thread_at = $thread_created;
        }
    }

    $now_gmt = current_time('mysql', true);
    $existing = $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $cases_table WHERE conversation_id = %d", $conversation_id),
        ARRAY_A
    );

    $primary_record_id = !empty($matches[0]['id']) ? absint($matches[0]['id']) : (isset($existing['primary_record_id']) ? absint($existing['primary_record_id']) : 0);
    $case_data = array(
        'conversation_id' => $conversation_id,
        'conversation_number' => $conversation_number,
        'mailbox_id' => $mailbox_id,
        'subject' => $subject,
        'preview' => $preview,
        'customer_name' => sanitize_text_field((string) ($customer['full_name'] ?? '')),
        'customer_email' => sanitize_email((string) ($customer['email'] ?? '')),
        'remote_status' => $remote_status,
        'remote_web_url' => $web_url,
        'primary_record_id' => $primary_record_id,
        'last_thread_at_gmt' => $last_thread_at,
        'last_customer_thread_at_gmt' => $last_customer_thread_at,
        'last_synced_gmt' => $now_gmt,
        'updated_at_gmt' => $now_gmt,
        'closed_in_help_scout' => $is_closed_remote ? 1 : 0,
        'payload' => wp_json_encode($conversation),
    );

    if ($existing) {
        $wpdb->update(
            $cases_table,
            $case_data,
            array('id' => (int) $existing['id'])
        );
        $case_id = (int) $existing['id'];
    } else {
        $case_data['imported_at_gmt'] = $now_gmt;
        $wpdb->insert($cases_table, $case_data);
        $case_id = (int) $wpdb->insert_id;
    }

    if ($case_id < 1) {
        return new WP_Error('help_scout_case_insert_failed', 'Failed to save Help Scout case in Order Hub.');
    }

    $wpdb->delete($links_table, array('case_id' => $case_id), array('%d'));
    foreach ($matches as $match) {
        $record_id = isset($match['id']) ? absint($match['id']) : 0;
        if ($record_id < 1) {
            continue;
        }
        $wpdb->insert(
            $links_table,
            array(
                'case_id' => $case_id,
                'record_id' => $record_id,
            ),
            array('%d', '%d')
        );
    }

    foreach ($threads as $thread) {
        if (!is_array($thread)) {
            continue;
        }
        $thread_id = isset($thread['id']) ? absint($thread['id']) : 0;
        if ($thread_id < 1) {
            continue;
        }

        $message_data = array(
            'case_id' => $case_id,
            'conversation_id' => $conversation_id,
            'thread_id' => $thread_id,
            'thread_type' => sanitize_key((string) ($thread['type'] ?? '')),
            'thread_status' => sanitize_key((string) ($thread['status'] ?? '')),
            'author_name' => np_order_hub_help_scout_extract_thread_author_name($thread),
            'author_email' => np_order_hub_help_scout_extract_thread_author_email($thread),
            'body' => np_order_hub_help_scout_extract_thread_body($thread),
            'created_at_gmt' => np_order_hub_help_scout_extract_thread_created_gmt($thread),
            'payload' => wp_json_encode($thread),
        );

        $existing_message_id = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM $messages_table WHERE conversation_id = %d AND thread_id = %d",
                $conversation_id,
                $thread_id
            )
        );
        if ($existing_message_id > 0) {
            $wpdb->update(
                $messages_table,
                $message_data,
                array('id' => $existing_message_id)
            );
        } else {
            $wpdb->insert($messages_table, $message_data);
        }
    }

    return np_order_hub_help_scout_get_case($case_id);
}

function np_order_hub_help_scout_mark_case_closed_in_remote($conversation_id, $closed = true) {
    np_order_hub_ensure_help_scout_case_tables();
    global $wpdb;
    $cases_table = np_order_hub_help_scout_cases_table_name();
    $wpdb->update(
        $cases_table,
        array(
            'closed_in_help_scout' => $closed ? 1 : 0,
            'remote_status' => $closed ? 'closed' : 'active',
            'updated_at_gmt' => current_time('mysql', true),
        ),
        array('conversation_id' => absint($conversation_id)),
        array('%d', '%s', '%s'),
        array('%d')
    );
}

function np_order_hub_help_scout_set_case_status($case, $status) {
    $status = np_order_hub_help_scout_normalize_case_status($status);
    if (!in_array($status, array('active', 'closed'), true)) {
        return new WP_Error('invalid_help_scout_case_status', 'Invalid Help Scout case status.');
    }

    if (!is_array($case)) {
        $case = np_order_hub_help_scout_get_case(absint($case));
    }
    if (empty($case) || !is_array($case)) {
        return new WP_Error('missing_help_scout_case', 'Help Scout case not found.');
    }

    $conversation_id = isset($case['conversation_id']) ? absint($case['conversation_id']) : 0;
    if ($conversation_id < 1) {
        return new WP_Error('missing_help_scout_conversation', 'Help Scout conversation ID missing.');
    }

    $settings = np_order_hub_get_help_scout_settings();
    $result = np_order_hub_help_scout_update_conversation_status($settings, $conversation_id, $status);
    if (is_wp_error($result)) {
        return $result;
    }

    np_order_hub_help_scout_mark_case_closed_in_remote($conversation_id, $status === 'closed');
    $updated_case = np_order_hub_help_scout_get_case_by_conversation_id($conversation_id);

    return is_array($updated_case) ? $updated_case : $case;
}

function np_order_hub_help_scout_get_case($case_id) {
    np_order_hub_ensure_help_scout_case_tables();
    $case_id = absint($case_id);
    if ($case_id < 1) {
        return null;
    }

    global $wpdb;
    $table = np_order_hub_help_scout_cases_table_name();
    return $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $table WHERE id = %d", $case_id),
        ARRAY_A
    );
}

function np_order_hub_help_scout_get_case_by_conversation_id($conversation_id) {
    np_order_hub_ensure_help_scout_case_tables();
    $conversation_id = absint($conversation_id);
    if ($conversation_id < 1) {
        return null;
    }

    global $wpdb;
    $table = np_order_hub_help_scout_cases_table_name();
    return $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $table WHERE conversation_id = %d", $conversation_id),
        ARRAY_A
    );
}

function np_order_hub_help_scout_get_case_links($case_id) {
    np_order_hub_ensure_help_scout_case_tables();
    $case_id = absint($case_id);
    if ($case_id < 1) {
        return array();
    }

    global $wpdb;
    $links_table = np_order_hub_help_scout_case_links_table_name();
    $orders_table = np_order_hub_table_name();
    return $wpdb->get_results(
        $wpdb->prepare(
            "SELECT o.* FROM $links_table l INNER JOIN $orders_table o ON o.id = l.record_id WHERE l.case_id = %d ORDER BY o.date_created_gmt DESC, o.id DESC",
            $case_id
        ),
        ARRAY_A
    );
}

function np_order_hub_help_scout_get_cases_for_record($record_id) {
    np_order_hub_ensure_help_scout_case_tables();
    $record_id = absint($record_id);
    if ($record_id < 1) {
        return array();
    }

    global $wpdb;
    $cases_table = np_order_hub_help_scout_cases_table_name();
    $links_table = np_order_hub_help_scout_case_links_table_name();
    return $wpdb->get_results(
        $wpdb->prepare(
            "SELECT c.* FROM $links_table l INNER JOIN $cases_table c ON c.id = l.case_id WHERE l.record_id = %d ORDER BY c.last_thread_at_gmt DESC, c.id DESC",
            $record_id
        ),
        ARRAY_A
    );
}

function np_order_hub_help_scout_get_case_messages($case_id) {
    np_order_hub_ensure_help_scout_case_tables();
    $case_id = absint($case_id);
    if ($case_id < 1) {
        return array();
    }

    global $wpdb;
    $table = np_order_hub_help_scout_messages_table_name();
    return $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table WHERE case_id = %d ORDER BY created_at_gmt ASC, id ASC",
            $case_id
        ),
        ARRAY_A
    );
}

function np_order_hub_help_scout_sync_conversation_to_local($settings, $conversation_id, $matches = array(), $close_remote = false) {
    $conversation = np_order_hub_help_scout_get_conversation_with_threads($settings, $conversation_id);
    if (is_wp_error($conversation)) {
        return $conversation;
    }

    if (empty($matches)) {
        $existing = np_order_hub_help_scout_get_case_by_conversation_id($conversation_id);
        if ($existing) {
            $matches = np_order_hub_help_scout_get_case_links((int) $existing['id']);
        }
    }

    $case = np_order_hub_help_scout_upsert_local_case($conversation, $matches);
    if (is_wp_error($case)) {
        return $case;
    }

    if ($close_remote) {
        $closed = np_order_hub_help_scout_update_conversation_status($settings, $conversation_id, 'closed');
        if (!is_wp_error($closed)) {
            np_order_hub_help_scout_mark_case_closed_in_remote($conversation_id, true);
            $case = np_order_hub_help_scout_get_case((int) $case['id']);
        }
    }

    return $case;
}

function np_order_hub_help_scout_case_preview($case) {
    if (!is_array($case)) {
        return '';
    }

    $preview = trim((string) ($case['preview'] ?? ''));
    if ($preview !== '') {
        return $preview;
    }

    $messages = np_order_hub_help_scout_get_case_messages(isset($case['id']) ? (int) $case['id'] : 0);
    if (empty($messages)) {
        return '';
    }

    $last = end($messages);
    if (!is_array($last)) {
        return '';
    }

    return wp_trim_words(wp_strip_all_tags((string) ($last['body'] ?? '')), 18, '…');
}

function np_order_hub_help_scout_case_message_html($message) {
    $body = isset($message['body']) ? (string) $message['body'] : '';
    if ($body === '') {
        return '<em>Tom melding</em>';
    }

    $body = trim($body);
    if (strpos($body, '<') !== false && strpos($body, '>') !== false) {
        return wp_kses_post($body);
    }

    return nl2br(esc_html($body));
}
