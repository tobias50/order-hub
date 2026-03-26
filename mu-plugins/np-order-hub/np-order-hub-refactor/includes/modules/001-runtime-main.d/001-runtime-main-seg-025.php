<?php
add_shortcode('np_order_hub_revenue_dashboard', 'np_order_hub_revenue_dashboard_shortcode');

function np_order_hub_help_scout_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $notice = '';
    $notice_type = 'updated';
    $current_user_id = get_current_user_id();
    $redirect_url = np_order_hub_help_scout_get_redirect_url();
    $webhook_url = np_order_hub_help_scout_get_webhook_url();

    $flash_key = 'np_order_hub_help_scout_notice_' . $current_user_id;
    $flash = get_transient($flash_key);
    if (is_array($flash) && !empty($flash['message'])) {
        $notice = (string) $flash['message'];
        $notice_type = !empty($flash['type']) && $flash['type'] === 'error' ? 'error' : 'updated';
        delete_transient($flash_key);
    }

    $settings = np_order_hub_get_help_scout_settings();

    if (!empty($_GET['help_scout_action'])) {
        $action = sanitize_key((string) $_GET['help_scout_action']);
        if ($action === 'connect') {
            $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field((string) wp_unslash($_GET['_wpnonce'])) : '';
            if (!wp_verify_nonce($nonce, 'np_order_hub_help_scout_connect')) {
                set_transient($flash_key, array('type' => 'error', 'message' => 'Connect-lenken er utløpt. Last siden på nytt og prøv igjen.'), 30);
                np_order_hub_redirect_with_fallback($redirect_url);
            }
            if ($settings['client_id'] === '' || $settings['client_secret'] === '') {
                set_transient($flash_key, array('type' => 'error', 'message' => 'Add App ID and App Secret first.'), 30);
                np_order_hub_redirect_with_fallback($redirect_url);
            }
            $state = wp_generate_password(12, false);
            set_transient('np_order_hub_help_scout_state_' . $current_user_id, $state, 10 * MINUTE_IN_SECONDS);
            $auth_url = add_query_arg(array(
                'client_id' => $settings['client_id'],
                'redirect_uri' => np_order_hub_help_scout_get_redirect_url(),
                'response_type' => 'code',
                'state' => $state,
            ), 'https://secure.helpscout.net/authentication/authorizeClientApplication');
            np_order_hub_redirect_with_fallback($auth_url);
        }
        if ($action === 'disconnect') {
            $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field((string) wp_unslash($_GET['_wpnonce'])) : '';
            if (!wp_verify_nonce($nonce, 'np_order_hub_help_scout_disconnect')) {
                set_transient($flash_key, array('type' => 'error', 'message' => 'Disconnect-lenken er utløpt. Last siden på nytt og prøv igjen.'), 30);
                np_order_hub_redirect_with_fallback($redirect_url);
            }
            update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, '');
            update_option(NP_ORDER_HUB_HELP_SCOUT_REFRESH_TOKEN_OPTION, '');
            update_option(NP_ORDER_HUB_HELP_SCOUT_EXPIRES_AT_OPTION, 0);
            set_transient($flash_key, array('type' => 'updated', 'message' => 'Help Scout disconnected.'), 30);
            np_order_hub_redirect_with_fallback($redirect_url);
        }
    }

    if (!empty($_GET['code']) || !empty($_GET['error'])) {
        $state = sanitize_text_field((string) ($_GET['state'] ?? ''));
        $expected_state = get_transient('np_order_hub_help_scout_state_' . $current_user_id);
        delete_transient('np_order_hub_help_scout_state_' . $current_user_id);

        if (!empty($_GET['error'])) {
            $error_message = sanitize_text_field((string) ($_GET['error_description'] ?? 'Help Scout OAuth failed.'));
            set_transient($flash_key, array('type' => 'error', 'message' => $error_message), 30);
        } elseif (!$expected_state || $state !== $expected_state) {
            set_transient($flash_key, array('type' => 'error', 'message' => 'Help Scout OAuth state mismatch.'), 30);
        } else {
            $result = np_order_hub_help_scout_exchange_code($settings, sanitize_text_field((string) $_GET['code']));
            if (is_wp_error($result)) {
                set_transient($flash_key, array('type' => 'error', 'message' => $result->get_error_message()), 30);
            } else {
                set_transient($flash_key, array('type' => 'updated', 'message' => 'Help Scout connected.'), 30);
            }
        }

        np_order_hub_redirect_with_fallback($redirect_url);
    }

    if (!empty($_POST['np_order_hub_save_help_scout']) && check_admin_referer('np_order_hub_save_help_scout')) {
        $token = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_token'] ?? ''));
        $mailbox_id = absint($_POST['np_order_hub_help_scout_mailbox'] ?? 0);
        $status = sanitize_key((string) ($_POST['np_order_hub_help_scout_default_status'] ?? 'pending'));
        if (!in_array($status, array('active', 'pending', 'closed'), true)) {
            $status = 'pending';
        }
        $user_id = absint($_POST['np_order_hub_help_scout_user'] ?? 0);
        $client_id = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_client_id'] ?? ''));
        $client_secret = sanitize_text_field((string) ($_POST['np_order_hub_help_scout_client_secret'] ?? ''));
        $webhook_secret = isset($_POST['np_order_hub_help_scout_webhook_secret']) ? trim((string) wp_unslash($_POST['np_order_hub_help_scout_webhook_secret'])) : '';
        $auto_lookup = !empty($_POST['np_order_hub_help_scout_auto_lookup']) ? 1 : 0;
        $local_inbox = !empty($_POST['np_order_hub_help_scout_local_inbox']) ? 1 : 0;
        $close_imported = !empty($_POST['np_order_hub_help_scout_close_imported']) ? 1 : 0;

        if ($token !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, $token);
        }
        update_option(NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION, $mailbox_id);
        update_option(NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION, $status);
        update_option(NP_ORDER_HUB_HELP_SCOUT_USER_OPTION, $user_id);
        update_option(NP_ORDER_HUB_HELP_SCOUT_AUTO_LOOKUP_OPTION, $auto_lookup);
        update_option(NP_ORDER_HUB_HELP_SCOUT_LOCAL_INBOX_OPTION, $local_inbox);
        update_option(NP_ORDER_HUB_HELP_SCOUT_CLOSE_IMPORTED_OPTION, $close_imported);
        if ($client_id !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_ID_OPTION, $client_id);
        }
        if ($client_secret !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_CLIENT_SECRET_OPTION, $client_secret);
        }
        if ($webhook_secret !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_WEBHOOK_SECRET_OPTION, $webhook_secret);
        }

        $notice = 'Settings saved.';
        $notice_type = 'updated';
        $settings = np_order_hub_get_help_scout_settings();
    }

    $connected = ($settings['token'] !== '' || $settings['refresh_token'] !== '');
    $connect_url = wp_nonce_url(add_query_arg('help_scout_action', 'connect', $redirect_url), 'np_order_hub_help_scout_connect');
    $disconnect_url = wp_nonce_url(add_query_arg('help_scout_action', 'disconnect', $redirect_url), 'np_order_hub_help_scout_disconnect');

    echo '<div class="wrap">';
    echo '<h1>Help Scout</h1>';
    if ($notice !== '') {
        echo '<div class="' . esc_attr($notice_type) . '"><p>' . esc_html($notice) . '</p></div>';
    }
    echo '<p class="description">Redirect URL for the Help Scout app: <code>' . esc_html($redirect_url) . '</code></p>';
    echo '<p>';
    if ($connected) {
        echo '<span class="description" style="margin-right:12px;">Connected.</span>';
        echo '<a class="button" href="' . esc_url($disconnect_url) . '">Disconnect</a>';
    } else {
        echo '<a class="button button-primary" href="' . esc_url($connect_url) . '" target="_blank" rel="noopener">Connect Help Scout</a>';
        echo '<span class="description" style="margin-left:10px;">Åpner autorisering i ny fane.</span>';
    }
    echo '</p>';
    if ($settings['token'] !== '' && $settings['refresh_token'] === '') {
        echo '<p class="description" style="color:#b91c1c;">Refresh token mangler. Trykk Disconnect og Connect Help Scout for å koble til på nytt.</p>';
    }
    if (!empty($settings['auto_lookup']) && $settings['webhook_secret'] === '') {
        echo '<p class="description" style="color:#b91c1c;">Auto lookup er aktivert, men Webhook secret mangler. Legg inn secret fra Help Scout webhook-oppsettet.</p>';
    }

    echo '<form method="post">';
    wp_nonce_field('np_order_hub_save_help_scout');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-client-id">App ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-client-id" name="np_order_hub_help_scout_client_id" type="text" class="regular-text" value="' . esc_attr($settings['client_id']) . '" /></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-client-secret">App Secret</label></th>';
    echo '<td><input id="np-order-hub-help-scout-client-secret" name="np_order_hub_help_scout_client_secret" type="password" class="regular-text" value="" />';
    echo '<p class="description">Leave blank to keep the current secret.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-token">API token</label></th>';
    echo '<td><input id="np-order-hub-help-scout-token" name="np_order_hub_help_scout_token" type="password" class="regular-text" value="" />';
    echo '<p class="description">Optional. Use a personal access token if you prefer manual setup.</p></td></tr>';
    echo '<tr><th scope="row">Current access token</th><td>';
    if ($settings['token'] !== '') {
        echo '<input id="np-order-hub-help-scout-token-current" type="password" class="regular-text" value="' . esc_attr($settings['token']) . '" readonly /> ';
        echo '<button type="button" class="button" id="np-order-hub-help-scout-token-toggle">Show</button>';
        echo '<p class="description">OAuth access token stored in WordPress. Do not share.</p>';
    } else {
        echo '<span class="description">No token stored.</span>';
    }
    echo '</td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-mailbox">Mailbox ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-mailbox" name="np_order_hub_help_scout_mailbox" type="number" class="small-text" value="' . esc_attr((string) $settings['mailbox_id']) . '" />';
    echo '<p class="description">Find the mailbox ID in Help Scout settings or the URL.</p></td></tr>';
    echo '<tr><th scope="row">Inbound webhook URL</th>';
    echo '<td><code>' . esc_html($webhook_url) . '</code>';
    echo '<p class="description">Legg denne URL-en inn i Help Scout Webhooks. Anbefalte events: <code>convo.created</code> og <code>convo.customer.reply.created</code>.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-webhook-secret">Webhook secret</label></th>';
    echo '<td><input id="np-order-hub-help-scout-webhook-secret" name="np_order_hub_help_scout_webhook_secret" type="password" class="regular-text" value="" />';
    echo '<p class="description">Leave blank to keep current secret. Current secret: ' . ($settings['webhook_secret'] !== '' ? 'configured' : 'missing') . '.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-auto-lookup">Auto lookup</label></th>';
    echo '<td><label><input id="np-order-hub-help-scout-auto-lookup" name="np_order_hub_help_scout_auto_lookup" type="checkbox" value="1"' . checked(!empty($settings['auto_lookup']), true, false) . ' /> Match innkommende Help Scout-samtaler mot ordre automatisk</label></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-local-inbox">Lokal saksinnboks</label></th>';
    echo '<td><label><input id="np-order-hub-help-scout-local-inbox" name="np_order_hub_help_scout_local_inbox" type="checkbox" value="1"' . checked(!empty($settings['local_inbox']), true, false) . ' /> Lagre koblede Help Scout-samtaler som saker i Order Hub</label>';
    echo '<p class="description">Når aktiv, opprettes lokale saker i Order Hub i stedet for at løsningen bare legger intern note i Help Scout.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-close-imported">Lukk i Help Scout</label></th>';
    echo '<td><label><input id="np-order-hub-help-scout-close-imported" name="np_order_hub_help_scout_close_imported" type="checkbox" value="1"' . checked(!empty($settings['close_imported']), true, false) . ' /> Lukk koblede samtaler i Help Scout etter import</label>';
    echo '<p class="description">Anbefalt. Dette tar saken ut av aktiv Help Scout-kø, men beholder API-sporet slik at du fortsatt kan svare fra Order Hub.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-user">Sender user ID</label></th>';
    echo '<td><input id="np-order-hub-help-scout-user" name="np_order_hub_help_scout_user" type="number" class="small-text" value="' . esc_attr((string) $settings['user_id']) . '" />';
    echo '<p class="description">Required to send outbound email.</p></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-help-scout-status">Default status</label></th>';
    echo '<td><select id="np-order-hub-help-scout-status" name="np_order_hub_help_scout_default_status">';
    $status_options = array(
        'pending' => 'Pending',
        'active' => 'Active',
        'closed' => 'Closed',
    );
    foreach ($status_options as $key => $label) {
        $selected = selected($settings['default_status'], $key, false);
        echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
    }
    echo '</select></td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_save_help_scout" value="1">Save settings</button></p>';
    echo '</form>';
    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var field = document.getElementById("np-order-hub-help-scout-token-current");
            var button = document.getElementById("np-order-hub-help-scout-token-toggle");
            if (!field || !button) {
                return;
            }
            button.addEventListener("click", function() {
                var showing = field.type === "text";
                field.type = showing ? "password" : "text";
                button.textContent = showing ? "Show" : "Hide";
            });
        });
    </script>';
    echo '</div>';
}

function np_order_hub_format_meta_lines($meta_data) {
    if (!is_array($meta_data)) {
        return array();
    }
    $lines = array();
    foreach ($meta_data as $meta) {
        if (!is_array($meta)) {
            continue;
        }
        $key = '';
        if (!empty($meta['display_key'])) {
            $key = (string) $meta['display_key'];
        } elseif (!empty($meta['key'])) {
            $key = (string) $meta['key'];
        }
        $key = trim($key);
        if ($key === '' || strpos($key, '_') === 0) {
            continue;
        }
        $value = '';
        if (isset($meta['display_value'])) {
            $value = $meta['display_value'];
        } elseif (isset($meta['value'])) {
            $value = $meta['value'];
        }
        if (is_array($value) || is_object($value)) {
            $value = wp_json_encode($value);
        }
        $value = trim((string) $value);
        if ($value === '') {
            continue;
        }
        $lines[] = $key . ': ' . $value;
    }
    return $lines;
}

function np_order_hub_sanitize_order_editor_address_input($raw, $type) {
    $raw = is_array($raw) ? $raw : array();
    $type = $type === 'shipping' ? 'shipping' : 'billing';
    $fields = array(
        'first_name',
        'last_name',
        'company',
        'address_1',
        'address_2',
        'postcode',
        'city',
        'state',
        'country',
    );
    if ($type === 'billing') {
        $fields[] = 'email';
        $fields[] = 'phone';
    }
    if ($type === 'shipping') {
        $fields[] = 'phone';
    }

    $sanitized = array();
    foreach ($fields as $field) {
        if (!array_key_exists($field, $raw)) {
            continue;
        }
        $value = is_scalar($raw[$field]) ? (string) $raw[$field] : '';
        if ($field === 'email') {
            $sanitized[$field] = sanitize_email($value);
        } elseif ($field === 'country') {
            $sanitized[$field] = strtoupper(sanitize_text_field($value));
        } else {
            $sanitized[$field] = sanitize_text_field($value);
        }
    }

    return $sanitized;
}

function np_order_hub_render_order_editor_address_fields($prefix, $values, $type) {
    $values = is_array($values) ? $values : array();
    $type = $type === 'shipping' ? 'shipping' : 'billing';
    $fields = array(
        'first_name' => 'First name',
        'last_name' => 'Last name',
        'company' => 'Company',
        'address_1' => 'Address line 1',
        'address_2' => 'Address line 2',
        'postcode' => 'Postcode',
        'city' => 'City',
        'state' => 'State / county',
        'country' => 'Country',
    );
    if ($type === 'billing') {
        $fields['email'] = 'Email';
        $fields['phone'] = 'Phone';
    } else {
        $fields['phone'] = 'Phone';
    }

    echo '<table class="form-table" style="margin-top:0;">';
    foreach ($fields as $field => $label) {
        $field_id = 'np-order-hub-' . esc_attr($prefix . '-' . $field);
        $name = 'order_' . $prefix . '[' . $field . ']';
        $value = isset($values[$field]) ? (string) $values[$field] : '';
        echo '<tr>';
        echo '<th scope="row"><label for="' . $field_id . '">' . esc_html($label) . '</label></th>';
        echo '<td><input id="' . $field_id . '" name="' . esc_attr($name) . '" type="text" class="regular-text" value="' . esc_attr($value) . '" /></td>';
        echo '</tr>';
    }
    echo '</table>';
}

function np_order_hub_render_order_editor_notes_list($notes) {
    $notes = is_array($notes) ? $notes : array();
    if (empty($notes)) {
        echo '<p class="description">No recent order notes found.</p>';
        return;
    }

    echo '<ul class="np-oh-order-notes">';
    foreach ($notes as $note) {
        if (!is_array($note)) {
            continue;
        }
        $created = trim((string) ($note['date_created_gmt'] ?? ''));
        $created_label = $created !== '' && $created !== '0000-00-00 00:00:00'
            ? get_date_from_gmt($created, 'd.m.Y H:i')
            : '—';
        $type = !empty($note['is_customer_note']) ? 'Customer note' : 'Internal';
        $author = trim((string) ($note['added_by'] ?? ''));
        if ($author === '') {
            $author = !empty($note['added_by_user']) ? 'User' : 'System';
        }
        $message = trim((string) ($note['note'] ?? ''));
        echo '<li class="np-oh-order-note">';
        echo '<div class="np-oh-order-note-meta">';
        echo '<strong>' . esc_html($type) . '</strong>';
        echo '<span>' . esc_html($created_label) . '</span>';
        echo '<span>' . esc_html($author) . '</span>';
        echo '</div>';
        echo '<div class="np-oh-order-note-body">' . esc_html($message !== '' ? $message : '—') . '</div>';
        echo '</li>';
    }
    echo '</ul>';
}

function np_order_hub_render_order_editor_styles() {
    echo '<style>
        .np-oh-editor-screen.wrap{max-width:1380px}
        .np-oh-editor-screen #poststuff{padding-top:0}
        .np-oh-editor-screen #post-body.columns-2{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:20px;margin:0;align-items:start}
        .np-oh-editor-screen #postbox-container-1,
        .np-oh-editor-screen #postbox-container-2{float:none!important;width:auto!important;margin:0!important}
        .np-oh-editor-screen #postbox-container-1{grid-column:2}
        .np-oh-editor-screen #postbox-container-2{grid-column:1;min-width:0}
        .np-oh-editor-screen .postbox{margin:0 0 16px}
        .np-oh-editor-screen .postbox .hndle{margin:0;padding:11px 12px;border-bottom:1px solid #ccd0d4;font-size:13px;font-weight:600}
        .np-oh-editor-screen .inside{margin:0;padding:12px}
        .np-oh-editor-screen .order_data_column_container{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
        .np-oh-editor-screen .order_data_column h3,
        .np-oh-editor-screen .np-oh-items-section h3,
        .np-oh-editor-screen .np-oh-notes-grid h3{margin:0 0 12px;padding-bottom:8px;border-bottom:1px solid #eee;font-size:13px}
        .np-oh-editor-screen .np-oh-readonly-list p{margin:0 0 8px}
        .np-oh-editor-screen .np-oh-two-col{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
        .np-oh-editor-screen .np-oh-item-summary{display:flex;gap:12px;align-items:flex-start}
        .np-oh-editor-screen .np-oh-item-thumb img{display:block;width:44px;height:44px;object-fit:cover;border:1px solid #ccd0d4;border-radius:2px;background:#fff}
        .np-oh-editor-screen .np-oh-item-copy strong{display:block;margin-bottom:4px}
        .np-oh-editor-screen .np-oh-item-meta{margin:6px 0 0 18px}
        .np-oh-editor-screen .np-oh-item-meta li{margin:0 0 4px}
        .np-oh-editor-screen .np-oh-qty-input{width:76px}
        .np-oh-editor-screen .np-oh-amount{text-align:right;white-space:nowrap}
        .np-oh-editor-screen .np-oh-items-table td,
        .np-oh-editor-screen .np-oh-items-table th{vertical-align:top}
        .np-oh-editor-screen .np-oh-items-table tfoot th,
        .np-oh-editor-screen .np-oh-items-table tfoot td{background:#fafafa}
        .np-oh-editor-screen .np-oh-items-section + .np-oh-items-section{margin-top:18px}
        .np-oh-editor-screen .np-oh-items-table .column-cost,
        .np-oh-editor-screen .np-oh-items-table .column-qty,
        .np-oh-editor-screen .np-oh-items-table .column-total{width:110px}
        .np-oh-editor-screen .np-oh-sidebar-form + .np-oh-sidebar-form{margin-top:14px;padding-top:14px;border-top:1px solid #eee}
        .np-oh-editor-screen .np-oh-sidebar-actions .button{margin:0 8px 8px 0}
        .np-oh-editor-screen .np-oh-sidebar-actions select,
        .np-oh-editor-screen .np-oh-sidebar-actions input[type=text]{width:100%}
        .np-oh-editor-screen .np-oh-meta-list{margin:0}
        .np-oh-editor-screen .np-oh-meta-list dt{font-weight:600;margin:0 0 4px}
        .np-oh-editor-screen .np-oh-meta-list dd{margin:0 0 12px}
        .np-oh-editor-screen .np-oh-panel-actions .button-link-delete{padding:0}
        .np-oh-editor-screen .form-table th{width:120px;padding-left:0}
        .np-oh-editor-screen .form-table td{padding-right:0}
        .np-oh-editor-screen .regular-text,
        .np-oh-editor-screen .large-text,
        .np-oh-editor-screen textarea,
        .np-oh-editor-screen select{max-width:100%}
        .np-oh-editor-screen .np-oh-order-notes{margin:0;padding:0;list-style:none}
        .np-oh-editor-screen .np-oh-order-note{margin:0 0 12px;padding:10px 12px;background:#f6f7f7;border:1px solid #dcdcde;border-radius:3px}
        .np-oh-editor-screen .np-oh-order-note-meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px;font-size:12px;color:#50575e}
        .np-oh-editor-screen .np-oh-order-note-body{white-space:pre-wrap}
        .np-oh-editor-screen .np-oh-case-list{display:flex;flex-direction:column;gap:12px}
        .np-oh-editor-screen .np-oh-case-card{padding:12px;background:#f6f7f7;border:1px solid #dcdcde;border-radius:3px}
        .np-oh-editor-screen .np-oh-case-card p{margin:0 0 6px}
        .np-oh-editor-screen .np-oh-case-card .description{display:block;margin-top:2px}
        .np-oh-editor-screen .np-oh-case-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
        @media (max-width: 1080px){
            .np-oh-editor-screen #post-body.columns-2{grid-template-columns:1fr}
            .np-oh-editor-screen #postbox-container-1,
            .np-oh-editor-screen #postbox-container-2{grid-column:auto;width:100%!important}
        }
        @media (max-width: 960px){
            .np-oh-editor-screen .order_data_column_container{grid-template-columns:1fr}
        }
        @media (max-width: 860px){
            .np-oh-editor-screen .np-oh-two-col{grid-template-columns:1fr}
        }
    </style>';
}

function np_order_hub_render_order_editor_item_summary($item) {
    $item = is_array($item) ? $item : array();
    $name = isset($item['name']) ? (string) $item['name'] : 'Item';
    $sku = trim((string) ($item['sku'] ?? ''));
    $parent_name = trim((string) ($item['parent_name'] ?? ''));
    $image_src = '';
    if (!empty($item['image']) && is_array($item['image']) && !empty($item['image']['src'])) {
        $image_src = esc_url((string) $item['image']['src']);
    }
    $meta_lines = np_order_hub_format_meta_lines(isset($item['meta_data']) ? $item['meta_data'] : array());

    echo '<div class="np-oh-item-summary">';
    if ($image_src !== '') {
        echo '<div class="np-oh-item-thumb"><img src="' . $image_src . '" alt="" /></div>';
    }
    echo '<div class="np-oh-item-copy">';
    echo '<strong>' . esc_html($name) . '</strong>';
    if ($parent_name !== '' && $parent_name !== $name) {
        echo '<div class="description">Parent: ' . esc_html($parent_name) . '</div>';
    }
    if ($sku !== '') {
        echo '<div class="description">SKU: ' . esc_html($sku) . '</div>';
    }
    if (!empty($meta_lines)) {
        echo '<ul class="np-oh-item-meta">';
        foreach ($meta_lines as $meta_line) {
            echo '<li>' . esc_html($meta_line) . '</li>';
        }
        echo '</ul>';
    }
    echo '</div>';
    echo '</div>';
}

function np_order_hub_order_details_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (!empty($_POST['np_order_hub_delete_record'])) {
        check_admin_referer('np_order_hub_delete_record');
        $delete_id = isset($_POST['record_id']) ? absint($_POST['record_id']) : 0;
        if ($delete_id > 0) {
            global $wpdb;
            $table = np_order_hub_table_name();
            $wpdb->delete($table, array('id' => $delete_id), array('%d'));
        }
        wp_safe_redirect(admin_url('admin.php?page=np-order-hub&np_order_hub_deleted=1'));
        exit;
    }

    $record_id = isset($_GET['record_id']) ? (int) $_GET['record_id'] : 0;
    $record = null;
    if ($record_id > 0) {
        global $wpdb;
        $table = np_order_hub_table_name();
        $record = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM $table WHERE id = %d", $record_id),
            ARRAY_A
        );
    }

    $store = $record ? np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '') : null;
    $payload = np_order_hub_get_record_payload_data($record);
    $live_order_notice = null;
    $live_order = $payload;
    $live_billing = isset($live_order['billing']) && is_array($live_order['billing']) ? $live_order['billing'] : array();
    $live_shipping = isset($live_order['shipping']) && is_array($live_order['shipping']) ? $live_order['shipping'] : array();
    $order_notes = isset($live_order['order_notes']) && is_array($live_order['order_notes']) ? $live_order['order_notes'] : array();
    $email_actions = isset($live_order['email_actions']) && is_array($live_order['email_actions']) && !empty($live_order['email_actions'])
        ? $live_order['email_actions']
        : np_order_hub_get_supported_order_email_actions();
    $line_items = isset($live_order['line_items']) && is_array($live_order['line_items']) ? $live_order['line_items'] : array();
    $shipping_lines = isset($live_order['shipping_lines']) && is_array($live_order['shipping_lines']) ? $live_order['shipping_lines'] : array();
    $fee_lines = isset($live_order['fee_lines']) && is_array($live_order['fee_lines']) ? $live_order['fee_lines'] : array();
    $help_scout_billing = $live_billing;
    $help_scout_email = !empty($help_scout_billing['email']) ? sanitize_email((string) $help_scout_billing['email']) : '';
    $help_scout_first_name = !empty($help_scout_billing['first_name']) ? sanitize_text_field((string) $help_scout_billing['first_name']) : '';
    $help_scout_last_name = !empty($help_scout_billing['last_name']) ? sanitize_text_field((string) $help_scout_billing['last_name']) : '';
    $customer_note_value = isset($live_order['customer_note']) ? (string) $live_order['customer_note'] : '';
    $order_note_form_value = '';
    $order_email_action_value = 'customer_processing_order';
    $new_shipping_form = array(
        'method_title' => '',
        'method_id' => 'manual_shipping',
        'total' => '',
    );
    $new_fee_form = array(
        'name' => '',
        'amount' => '',
    );

    $help_scout_notice = null;
    $help_scout_form = array(
        'subject' => '',
        'message' => '',
        'status' => '',
    );
    if ($record && !empty($_POST['np_order_hub_help_scout_send'])) {
        check_admin_referer('np_order_hub_help_scout_send');
        $help_scout_form['subject'] = sanitize_text_field((string) ($_POST['help_scout_subject'] ?? ''));
        $help_scout_form['message'] = sanitize_textarea_field((string) ($_POST['help_scout_message'] ?? ''));
        $help_scout_form['status'] = sanitize_key((string) ($_POST['help_scout_status'] ?? ''));
        $help_scout_settings = np_order_hub_get_help_scout_settings();
        $help_scout_statuses = array('active', 'pending', 'closed');

        if (!in_array($help_scout_form['status'], $help_scout_statuses, true)) {
            $help_scout_form['status'] = $help_scout_settings['default_status'];
        }

        if ($help_scout_settings['token'] === '' || empty($help_scout_settings['mailbox_id'])) {
            $help_scout_notice = array('type' => 'error', 'message' => 'Help Scout settings are missing. Add an API token and mailbox ID.', 'allow_html' => false);
        } elseif ($help_scout_email === '') {
            $help_scout_notice = array('type' => 'error', 'message' => 'Customer email is missing on this order.', 'allow_html' => false);
        } elseif ($help_scout_form['subject'] === '' || $help_scout_form['message'] === '') {
            $help_scout_notice = array('type' => 'error', 'message' => 'Subject and message are required.', 'allow_html' => false);
        } else {
            $customer = array('email' => $help_scout_email);
            if ($help_scout_first_name !== '') {
                $customer['firstName'] = $help_scout_first_name;
            }
            if ($help_scout_last_name !== '') {
                $customer['lastName'] = $help_scout_last_name;
            }

            $result = np_order_hub_help_scout_create_conversation(
                $help_scout_settings,
                $customer,
                $help_scout_form['subject'],
                $help_scout_form['status'],
                $help_scout_form['message']
            );
            if (is_wp_error($result)) {
                $help_scout_message = $result->get_error_message();
                $allow_html = false;
                $error_data = $result->get_error_data();
                if (is_array($error_data)) {
                    $request_body = isset($error_data['request_body']) ? (string) $error_data['request_body'] : '';
                    $request_headers = $error_data['request_headers'] ?? null;
                    $response_body = '';
                    if (isset($error_data['response_body'])) {
                        $response_body = (string) $error_data['response_body'];
                    } elseif (isset($error_data['body'])) {
                        $response_body = (string) $error_data['body'];
                    }
                    $response_headers = $error_data['response_headers'] ?? null;
                    $request_url = isset($error_data['request_url']) ? (string) $error_data['request_url'] : '';
                    if ($request_body !== '' || !empty($request_headers) || $response_body !== '' || !empty($response_headers)) {
                        $allow_html = true;
                        if ($request_url !== '') {
                            $help_scout_message .= ' <details><summary>Show request URL</summary><pre style="white-space:pre-wrap;">' . esc_html($request_url) . '</pre></details>';
                        }
                        if (!empty($request_headers)) {
                            $request_headers_text = is_string($request_headers) ? $request_headers : wp_json_encode($request_headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                            $help_scout_message .= ' <details><summary>Show request headers</summary><pre style="white-space:pre-wrap;">' . esc_html($request_headers_text) . '</pre></details>';
                        }
                        if ($request_body !== '') {
                            $help_scout_message .= ' <details><summary>Show request payload</summary><pre style="white-space:pre-wrap;">' . esc_html($request_body) . '</pre></details>';
                        }
                        if ($response_body !== '') {
                            $help_scout_message .= ' <details><summary>Show response body</summary><pre style="white-space:pre-wrap;">' . esc_html($response_body) . '</pre></details>';
                        }
                        if (!empty($response_headers)) {
                            $response_headers_text = is_string($response_headers) ? $response_headers : wp_json_encode($response_headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                            $help_scout_message .= ' <details><summary>Show response headers</summary><pre style="white-space:pre-wrap;">' . esc_html($response_headers_text) . '</pre></details>';
                        }
                    }
                }
                $help_scout_notice = array('type' => 'error', 'message' => $help_scout_message, 'allow_html' => $allow_html);
            } else {
                $message = 'Help Scout message sent to customer.';
                $allow_html = false;
                if (!empty($result['web_url'])) {
                    $message = 'Help Scout message sent. <a href="' . esc_url($result['web_url']) . '" target="_blank" rel="noopener">Open conversation</a>.';
                    $allow_html = true;
                }
                $help_scout_notice = array('type' => 'success', 'message' => $message, 'allow_html' => $allow_html);
                $help_scout_form = array('subject' => '', 'message' => '', 'status' => '');
            }
        }
    }

    if ($record && !empty($_POST['np_order_hub_refresh_live_order'])) {
        check_admin_referer('np_order_hub_refresh_live_order');
        $result = np_order_hub_fetch_remote_order_live($store, (int) $record['order_id']);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Live order data refreshed.');
        }
    }

    if ($record && !empty($_POST['np_order_hub_update_addresses'])) {
        check_admin_referer('np_order_hub_update_addresses');
        $billing_input = np_order_hub_sanitize_order_editor_address_input($_POST['order_billing'] ?? array(), 'billing');
        $shipping_input = np_order_hub_sanitize_order_editor_address_input($_POST['order_shipping'] ?? array(), 'shipping');
        $result = np_order_hub_update_remote_order_addresses($store, (int) $record['order_id'], $billing_input, $shipping_input);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Addresses updated.');
        }
    }

    if ($record && !empty($_POST['np_order_hub_add_order_note'])) {
        check_admin_referer('np_order_hub_add_order_note');
        $order_note_form_value = sanitize_textarea_field((string) ($_POST['order_note'] ?? ''));
        $result = np_order_hub_add_remote_order_note($store, (int) $record['order_id'], $order_note_form_value);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Order note added.');
            $order_note_form_value = '';
        }
    }

    if ($record && !empty($_POST['np_order_hub_update_customer_note'])) {
        check_admin_referer('np_order_hub_update_customer_note');
        $customer_note_value = sanitize_textarea_field((string) ($_POST['customer_note'] ?? ''));
        $result = np_order_hub_update_remote_customer_note($store, (int) $record['order_id'], $customer_note_value);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Customer note updated.');
        }
    }

    if ($record && !empty($_POST['np_order_hub_send_order_email'])) {
        check_admin_referer('np_order_hub_send_order_email');
        $order_email_action_value = sanitize_key((string) ($_POST['order_email_action'] ?? ''));
        $result = np_order_hub_send_remote_order_email($store, (int) $record['order_id'], $order_email_action_value);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $label = $email_actions[$order_email_action_value] ?? $order_email_action_value;
            $live_order_notice = array('type' => 'success', 'message' => 'Sent Woo email: ' . $label . '.');
        }
    }

    if ($record && !empty($_POST['np_order_hub_update_line_items'])) {
        check_admin_referer('np_order_hub_update_line_items');
        $posted_items = isset($_POST['line_items']) && is_array($_POST['line_items']) ? $_POST['line_items'] : array();
        $items_payload = array();
        foreach ($posted_items as $item_id => $item_row) {
            if (!is_array($item_row)) {
                continue;
            }
            $items_payload[] = array(
                'item_id' => absint($item_id),
                'quantity' => absint($item_row['quantity'] ?? 0),
            );
        }
        $result = np_order_hub_update_remote_order_items($store, (int) $record['order_id'], $items_payload);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Line items updated.');
        }
    }

    if ($record && !empty($_POST['np_order_hub_update_shipping'])) {
        check_admin_referer('np_order_hub_update_shipping');
        $posted_shipping = isset($_POST['shipping_lines']) && is_array($_POST['shipping_lines']) ? $_POST['shipping_lines'] : array();
        $shipping_payload = array();
        foreach ($posted_shipping as $item_id => $row) {
            if (!is_array($row)) {
                continue;
            }
            $shipping_payload[] = array(
                'item_id' => absint($item_id),
                'method_title' => sanitize_text_field((string) ($row['method_title'] ?? '')),
                'method_id' => sanitize_key((string) ($row['method_id'] ?? '')),
                'total' => np_order_hub_parse_numeric_value($row['total'] ?? null),
                'remove' => !empty($row['remove']) ? 1 : 0,
            );
        }
        $new_shipping_form = array(
            'method_title' => sanitize_text_field((string) ($_POST['new_shipping']['method_title'] ?? '')),
            'method_id' => sanitize_key((string) ($_POST['new_shipping']['method_id'] ?? 'manual_shipping')),
            'total' => (string) ($_POST['new_shipping']['total'] ?? ''),
        );
        $new_shipping_payload = array(
            'method_title' => $new_shipping_form['method_title'],
            'method_id' => $new_shipping_form['method_id'],
            'total' => np_order_hub_parse_numeric_value($new_shipping_form['total']),
        );
        $result = np_order_hub_update_remote_order_shipping($store, (int) $record['order_id'], $shipping_payload, $new_shipping_payload);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Shipping updated.');
            $new_shipping_form = array('method_title' => '', 'method_id' => 'manual_shipping', 'total' => '');
        }
    }

    if ($record && !empty($_POST['np_order_hub_update_fees'])) {
        check_admin_referer('np_order_hub_update_fees');
        $posted_fees = isset($_POST['fee_lines']) && is_array($_POST['fee_lines']) ? $_POST['fee_lines'] : array();
        $fee_payload = array();
        foreach ($posted_fees as $item_id => $row) {
            if (!is_array($row)) {
                continue;
            }
            $fee_payload[] = array(
                'item_id' => absint($item_id),
                'name' => sanitize_text_field((string) ($row['name'] ?? '')),
                'amount' => np_order_hub_parse_numeric_value($row['amount'] ?? null),
                'remove' => !empty($row['remove']) ? 1 : 0,
            );
        }
        $new_fee_form = array(
            'name' => sanitize_text_field((string) ($_POST['new_fee']['name'] ?? '')),
            'amount' => (string) ($_POST['new_fee']['amount'] ?? ''),
        );
        $new_fee_payload = array(
            'name' => $new_fee_form['name'],
            'amount' => np_order_hub_parse_numeric_value($new_fee_form['amount']),
        );
        $result = np_order_hub_update_remote_order_fees($store, (int) $record['order_id'], $fee_payload, $new_fee_payload);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Fees / discounts updated.');
            $new_fee_form = array('name' => '', 'amount' => '');
        }
    }

    if ($record && !empty($_POST['np_order_hub_recalculate_order'])) {
        check_admin_referer('np_order_hub_recalculate_order');
        $result = np_order_hub_recalculate_remote_order($store, (int) $record['order_id']);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Order totals recalculated.');
        }
    }

    $status_notice = null;
    if ($record && !empty($_POST['np_order_hub_update_status'])) {
        check_admin_referer('np_order_hub_update_status');
        $new_status = sanitize_key((string) $_POST['order_status']);
        $allowed_statuses = np_order_hub_get_allowed_statuses();
        if (!isset($allowed_statuses[$new_status])) {
            $status_notice = array('type' => 'error', 'message' => 'Invalid status selected.');
        } else {
            $result = np_order_hub_update_remote_order_status($store, (int) $record['order_id'], $new_status);
            if (is_wp_error($result)) {
                $status_notice = array('type' => 'error', 'message' => $result->get_error_message());
            } else {
                if (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
                    $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
                } else {
                    $record = np_order_hub_apply_local_status($record, $new_status);
                }
                $status_notice = array('type' => 'success', 'message' => 'Order status updated.');
            }
        }
    }

    $delivery_notice = null;
    if ($record && !empty($_POST['np_order_hub_update_delivery_bucket'])) {
        check_admin_referer('np_order_hub_update_delivery_bucket');
        $bucket = np_order_hub_normalize_delivery_bucket((string) ($_POST['delivery_bucket'] ?? ''));
        $record = np_order_hub_update_delivery_bucket($record, $bucket);
        $delivery_notice = array('type' => 'success', 'message' => 'Delivery bucket updated.');
    }

    $reklamasjon_notice = null;
    $reklamasjon_open = false;
    $reklamasjon_allow_oos = false;
    $reklamasjon_popup_message = '';
    $reklamasjon_selected_items = array();
    $reklamasjon_qty_input = array();
    if ($record && !empty($_POST['np_order_hub_create_reklamasjon'])) {
        $reklamasjon_open = true;
        check_admin_referer('np_order_hub_create_reklamasjon');
        $reklamasjon_allow_oos = !empty($_POST['reklamasjon_allow_oos']);
        $selected_items = isset($_POST['reklamasjon_items']) ? array_map('absint', (array) $_POST['reklamasjon_items']) : array();
        $selected_items = array_values(array_filter($selected_items, function ($value) {
            return $value > 0;
        }));
        $reklamasjon_selected_items = $selected_items;
        if (empty($line_items)) {
            $reklamasjon_notice = array('type' => 'error', 'message' => 'No line items found for this order.', 'allow_html' => false);
        } elseif (empty($selected_items)) {
            $reklamasjon_notice = array('type' => 'error', 'message' => 'Select at least one item for the claim order.', 'allow_html' => false);
        } else {
            $items_by_id = array();
            foreach ($line_items as $item) {
                if (!is_array($item) || empty($item['id'])) {
                    continue;
                }
                $items_by_id[(int) $item['id']] = $item;
            }

            $qty_input = isset($_POST['reklamasjon_qty']) && is_array($_POST['reklamasjon_qty']) ? $_POST['reklamasjon_qty'] : array();
            $reklamasjon_qty_input = $qty_input;
            $items_payload = array();
            $errors = array();
            foreach ($selected_items as $item_id) {
                if (empty($items_by_id[$item_id])) {
                    $errors[] = 'Selected item not found.';
                    continue;
                }
                $source = $items_by_id[$item_id];
                $max_qty = isset($source['quantity']) ? (int) $source['quantity'] : 0;
                $requested_qty = isset($qty_input[$item_id]) ? absint($qty_input[$item_id]) : $max_qty;
                if ($max_qty < 1 || $requested_qty < 1 || $requested_qty > $max_qty) {
                    $errors[] = 'Invalid quantity selected for one or more items.';
                    continue;
                }
                $items_payload[] = array(
                    'item_id' => (int) $item_id,
                    'quantity' => (int) $requested_qty,
                );
            }

            if (!empty($errors)) {
                $reklamasjon_notice = array('type' => 'error', 'message' => $errors[0], 'allow_html' => false);
            } elseif (empty($items_payload)) {
                $reklamasjon_notice = array('type' => 'error', 'message' => 'No valid items were selected.', 'allow_html' => false);
            } else {
                $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
                $result = np_order_hub_create_remote_reklamasjon_order($store, (int) $record['order_id'], $items_payload, $reklamasjon_allow_oos);
                if (is_wp_error($result)) {
                    if ($result->get_error_code() === 'stock_unavailable') {
                        $reklamasjon_popup_message = 'Produktet er utsolgt. Opprette reklamasjon og sette som restordre?';
                        $reklamasjon_notice = array('type' => 'error', 'message' => $result->get_error_message(), 'allow_html' => false);
                    } else {
                        $reklamasjon_notice = array('type' => 'error', 'message' => $result->get_error_message(), 'allow_html' => false);
                    }
                } else {
                    $new_order_id = isset($result['order_id']) ? (int) $result['order_id'] : 0;
                    $new_order_number = isset($result['order_number']) ? (string) $result['order_number'] : '';
                    $message = 'Claim order created.';
                    if ($new_order_id > 0) {
                        $label = $new_order_number !== '' ? ('#' . $new_order_number) : ('#' . $new_order_id);
                        $open_url = np_order_hub_build_admin_order_url($store, $new_order_id);
                        if ($open_url !== '') {
                            $message = 'Claim order created: <a href="' . esc_url($open_url) . '" target="_blank" rel="noopener">' . esc_html($label) . '</a>.';
                        } else {
                            $message = 'Claim order created: ' . esc_html($label) . '.';
                        }
                    }
                    $reklamasjon_notice = array('type' => 'success', 'message' => $message, 'allow_html' => true);
                }
            }
        }
    }

    if ($record && $store && np_order_hub_get_store_token($store) !== '') {
        $live_result = np_order_hub_fetch_remote_order_live($store, (int) $record['order_id']);
        if (!is_wp_error($live_result) && is_array($live_result) && !empty($live_result['order']) && is_array($live_result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $live_result['order']);
        }
    }

    $payload = np_order_hub_get_record_payload_data($record);
    $live_order = $payload;
    $live_billing = isset($live_order['billing']) && is_array($live_order['billing']) ? $live_order['billing'] : array();
    $live_shipping = isset($live_order['shipping']) && is_array($live_order['shipping']) ? $live_order['shipping'] : array();
    $order_notes = isset($live_order['order_notes']) && is_array($live_order['order_notes']) ? $live_order['order_notes'] : array();
    $email_actions = isset($live_order['email_actions']) && is_array($live_order['email_actions']) && !empty($live_order['email_actions'])
        ? $live_order['email_actions']
        : np_order_hub_get_supported_order_email_actions();
    $line_items = isset($live_order['line_items']) && is_array($live_order['line_items']) ? $live_order['line_items'] : array();
    $shipping_lines = isset($live_order['shipping_lines']) && is_array($live_order['shipping_lines']) ? $live_order['shipping_lines'] : array();
    $fee_lines = isset($live_order['fee_lines']) && is_array($live_order['fee_lines']) ? $live_order['fee_lines'] : array();
    $help_scout_billing = $live_billing;
    $help_scout_email = !empty($help_scout_billing['email']) ? sanitize_email((string) $help_scout_billing['email']) : '';
    $help_scout_first_name = !empty($help_scout_billing['first_name']) ? sanitize_text_field((string) $help_scout_billing['first_name']) : '';
    $help_scout_last_name = !empty($help_scout_billing['last_name']) ? sanitize_text_field((string) $help_scout_billing['last_name']) : '';
    $customer_note_value = isset($live_order['customer_note']) ? (string) $live_order['customer_note'] : $customer_note_value;

    echo '<div class="wrap woocommerce np-oh-editor-screen">';
    echo '<h1>Order Details</h1>';
    echo '<p><a href="' . esc_url(admin_url('admin.php?page=np-order-hub')) . '">&larr; Back to orders</a></p>';

    if (!empty($status_notice) && is_array($status_notice)) {
        $type = $status_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($status_notice['message']) ? (string) $status_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }

    if (!empty($delivery_notice) && is_array($delivery_notice)) {
        $type = $delivery_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($delivery_notice['message']) ? (string) $delivery_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }

    if (!empty($reklamasjon_notice) && is_array($reklamasjon_notice)) {
        $type = $reklamasjon_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($reklamasjon_notice['message']) ? (string) $reklamasjon_notice['message'] : '';
        if ($message !== '') {
            if (!empty($reklamasjon_notice['allow_html'])) {
                echo '<div class="' . esc_attr($type) . '"><p>' . wp_kses_post($message) . '</p></div>';
            } else {
                echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
            }
        }
    }

    if (!empty($help_scout_notice) && is_array($help_scout_notice)) {
        $type = $help_scout_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($help_scout_notice['message']) ? (string) $help_scout_notice['message'] : '';
        if ($message !== '') {
            if (!empty($help_scout_notice['allow_html'])) {
                echo '<div class="' . esc_attr($type) . '"><p>' . wp_kses_post($message) . '</p></div>';
            } else {
                echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
            }
        }
    }

    if (!empty($live_order_notice) && is_array($live_order_notice)) {
        $type = $live_order_notice['type'] === 'success' ? 'updated' : 'error';
        $message = isset($live_order_notice['message']) ? (string) $live_order_notice['message'] : '';
        if ($message !== '') {
            echo '<div class="' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
        }
    }

    if (!$record) {
        echo '<div class="error"><p>Order not found.</p></div>';
        echo '</div>';
        return;
    }

    $order_label = $record['order_number'] !== '' ? ('#' . $record['order_number']) : ('#' . $record['order_id']);
    $date_label = '';
    if (!empty($record['date_created_gmt']) && $record['date_created_gmt'] !== '0000-00-00 00:00:00') {
        $date_label = get_date_from_gmt($record['date_created_gmt'], 'd.m.y');
    }
    $status_label = $record['status'] !== '' ? ucwords(str_replace('-', ' ', $record['status'])) : '';
    $currency = $record['currency'] !== '' ? $record['currency'] : (isset($payload['currency']) ? (string) $payload['currency'] : '');
    $total = isset($payload['total']) ? (float) $payload['total'] : (float) $record['total'];
    $total_display = trim(number_format_i18n($total, 2) . ' ' . $currency);

    $modified_label = '';
    if (!empty($record['date_modified_gmt']) && $record['date_modified_gmt'] !== '0000-00-00 00:00:00') {
        $modified_label = get_date_from_gmt($record['date_modified_gmt'], 'd.m.Y H:i');
    }
    $allowed_statuses = np_order_hub_get_allowed_statuses();
    $delivery_bucket = np_order_hub_record_delivery_bucket($record);
    $packing_url = np_order_hub_build_packing_slip_url(
        $store,
        (int) $record['order_id'],
        (string) $record['order_number'],
        isset($record['payload']) ? $record['payload'] : null
    );
    $open_order_url = np_order_hub_get_order_admin_url_for_record($record);
    $token_missing = np_order_hub_get_store_token($store) === '';
    $payment_method_title = trim((string) ($live_order['payment_method_title'] ?? ''));
    $transaction_id = trim((string) ($live_order['transaction_id'] ?? ''));
    $created_via = trim((string) ($live_order['created_via'] ?? ''));
    $linked_cases = np_order_hub_help_scout_get_cases_for_record((int) $record['id']);

    np_order_hub_render_order_editor_styles();
    echo '<h1 class="wp-heading-inline">Edit order ' . esc_html($order_label) . '</h1>';
    echo '<a class="page-title-action" href="' . esc_url(admin_url('admin.php?page=np-order-hub')) . '">Back to hub</a>';
    echo '<div id="poststuff">';
    echo '<div id="post-body" class="metabox-holder columns-2">';
    echo '<div id="postbox-container-1" class="postbox-container">';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Order actions</h2>';
    echo '<div class="inside np-oh-sidebar-actions">';
    if (!empty($allowed_statuses)) {
        echo '<form class="np-oh-sidebar-form" method="post">';
        wp_nonce_field('np_order_hub_update_status');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<p><label for="np-order-hub-status-update"><strong>Status</strong></label></p>';
        echo '<select name="order_status" id="np-order-hub-status-update">';
        foreach ($allowed_statuses as $key => $label) {
            $selected = selected($record['status'], $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_status" value="1">Update</button></p>';
        if ($token_missing) {
            echo '<p class="description">Store token missing in hub store settings.</p>';
        }
        echo '</form>';
    }

    echo '<form class="np-oh-sidebar-form" method="post">';
    wp_nonce_field('np_order_hub_update_delivery_bucket');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<p><label for="np-order-hub-delivery-bucket"><strong>Delivery bucket</strong></label></p>';
    echo '<select name="delivery_bucket" id="np-order-hub-delivery-bucket">';
    echo '<option value="standard"' . selected($delivery_bucket, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_delivery_bucket" value="1">Update</button></p>';
    echo '</form>';

    echo '<form class="np-oh-sidebar-form" method="post">';
    wp_nonce_field('np_order_hub_send_order_email');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<p><label for="np-order-hub-email-action"><strong>Woo email</strong></label></p>';
    echo '<select name="order_email_action" id="np-order-hub-email-action">';
    foreach ($email_actions as $action_key => $action_label) {
        echo '<option value="' . esc_attr((string) $action_key) . '"' . selected($order_email_action_value, (string) $action_key, false) . '>' . esc_html((string) $action_label) . '</option>';
    }
    echo '</select>';
    echo '<p><button class="button" type="submit" name="np_order_hub_send_order_email" value="1">Send email</button></p>';
    echo '</form>';

    echo '<div class="np-oh-sidebar-form">';
    if ($packing_url !== '') {
        echo '<a class="button" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a>';
    }
    if ($open_order_url !== '') {
        echo '<a class="button button-primary" href="' . esc_url($open_order_url) . '" target="_blank" rel="noopener">Open in store</a>';
    }
    echo '<form method="post" style="margin-top:8px;">';
    wp_nonce_field('np_order_hub_refresh_live_order');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_refresh_live_order" value="1">Refresh live data</button>';
    echo '</form>';
    echo '<form method="post" style="margin-top:8px;">';
    wp_nonce_field('np_order_hub_delete_record');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button-link-delete" type="submit" name="np_order_hub_delete_record" value="1" onclick="return confirm(\'Remove this order from the hub?\');">Delete from hub</button>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Saker</h2>';
    echo '<div class="inside">';
    if (empty($linked_cases)) {
        echo '<p class="description">Ingen koblede saker for denne ordren.</p>';
    } else {
        echo '<div class="np-oh-case-list">';
        foreach ($linked_cases as $case) {
            $case_id = isset($case['id']) ? (int) $case['id'] : 0;
            $case_subject = trim((string) ($case['subject'] ?? ''));
            $case_customer = trim((string) (($case['customer_name'] ?? '') ?: ($case['customer_email'] ?? '')));
            $case_status = np_order_hub_help_scout_case_status_label((string) ($case['remote_status'] ?? ''));
            $case_last_thread = trim((string) ($case['last_thread_at_gmt'] ?? ''));
            $case_last_thread_label = $case_last_thread !== '' && $case_last_thread !== '0000-00-00 00:00:00'
                ? get_date_from_gmt($case_last_thread, 'd.m.Y H:i')
                : '—';
            $case_details_url = admin_url('admin.php?page=np-order-hub-case-details&case_id=' . $case_id);
            $case_remote_url = trim((string) ($case['remote_web_url'] ?? ''));

            echo '<div class="np-oh-case-card">';
            echo '<p><strong>' . esc_html($case_subject !== '' ? $case_subject : '(uten emne)') . '</strong></p>';
            echo '<p>' . esc_html($case_customer !== '' ? $case_customer : 'Ukjent') . '</p>';
            echo '<span class="description">Status: ' . esc_html($case_status) . '</span>';
            echo '<span class="description">Sist oppdatert: ' . esc_html($case_last_thread_label) . '</span>';
            echo '<div class="np-oh-case-actions">';
            echo '<a class="button button-small" href="' . esc_url($case_details_url) . '">Åpne sak</a>';
            if ($case_remote_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($case_remote_url) . '" target="_blank" rel="noopener">Help Scout</a>';
            }
            echo '</div>';
            echo '</div>';
        }
        echo '</div>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Customer note</h2>';
    echo '<div class="inside">';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_customer_note');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<textarea name="customer_note" rows="5" class="large-text">' . esc_textarea($customer_note_value) . '</textarea>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_customer_note" value="1">Save customer note</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Order notes</h2>';
    echo '<div class="inside">';
    echo '<h3>Add note</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_add_order_note');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<textarea name="order_note" rows="5" class="large-text">' . esc_textarea($order_note_form_value) . '</textarea>';
    echo '<p><button class="button" type="submit" name="np_order_hub_add_order_note" value="1">Add note</button></p>';
    echo '</form>';
    echo '<h3 style="margin-top:24px;">Recent notes</h3>';
    np_order_hub_render_order_editor_notes_list($order_notes);
    echo '</div>';
    echo '</div>';

    echo '</div>';

    echo '<div id="postbox-container-2" class="postbox-container">';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Order data</h2>';
    echo '<div class="inside">';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_addresses');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<div class="order_data_column_container">';
    echo '<div class="order_data_column">';
    echo '<h3>General</h3>';
    echo '<div class="np-oh-readonly-list">';
    echo '<p><strong>Order:</strong> ' . esc_html($order_label) . '</p>';
    echo '<p><strong>Store:</strong> ' . esc_html($record['store_name']) . '</p>';
    if ($date_label !== '') {
        echo '<p><strong>Created:</strong> ' . esc_html($date_label) . '</p>';
    }
    if ($modified_label !== '') {
        echo '<p><strong>Live synced:</strong> ' . esc_html($modified_label) . '</p>';
    }
    echo '<p><strong>Total:</strong> ' . esc_html($total_display) . '</p>';
    echo '<p><strong>Payment method:</strong> ' . esc_html($payment_method_title !== '' ? $payment_method_title : '—') . '</p>';
    echo '<p><strong>Transaction ID:</strong> ' . esc_html($transaction_id !== '' ? $transaction_id : '—') . '</p>';
    echo '<p><strong>Created via:</strong> ' . esc_html($created_via !== '' ? $created_via : '—') . '</p>';
    echo '</div>';
    echo '</div>';
    echo '<div class="order_data_column">';
    echo '<h3>Billing</h3>';
    np_order_hub_render_order_editor_address_fields('billing', $live_billing, 'billing');
    echo '</div>';
    echo '<div class="order_data_column">';
    echo '<h3>Shipping</h3>';
    np_order_hub_render_order_editor_address_fields('shipping', $live_shipping, 'shipping');
    echo '</div>';
    echo '</div>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_addresses" value="1">Save order data</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Order items</h2>';
    echo '<div class="inside">';
    echo '<p class="description">Hub follows the store order. Product rows can only be adjusted by quantity here.</p>';
    echo '<div class="np-oh-items-section">';
    if (empty($line_items)) {
        echo '<p class="description">No line items found.</p>';
    } else {
        echo '<form method="post">';
        wp_nonce_field('np_order_hub_update_line_items');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="widefat striped np-oh-items-table">';
        echo '<thead><tr><th>Item</th><th class="column-cost np-oh-amount">Cost</th><th class="column-qty">Qty</th><th class="column-total np-oh-amount">Total</th></tr></thead><tbody>';
        foreach ($line_items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $item_id = isset($item['id']) ? (int) $item['id'] : 0;
            if ($item_id < 1) {
                continue;
            }
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $total_value = is_numeric($total_raw) ? (float) $total_raw : 0.0;
            $unit_cost = $qty > 0 ? ($total_value / $qty) : $total_value;
            echo '<tr>';
            echo '<td>';
            np_order_hub_render_order_editor_item_summary($item);
            echo '</td>';
            echo '<td class="np-oh-amount">' . esc_html(trim(number_format_i18n($unit_cost, 2) . ' ' . $currency)) . '</td>';
            echo '<td><input class="np-oh-qty-input" type="number" min="1" name="line_items[' . esc_attr((string) $item_id) . '][quantity]" value="' . esc_attr((string) max(1, $qty)) . '" /></td>';
            echo '<td class="np-oh-amount">' . esc_html(trim(number_format_i18n($total_value, 2) . ' ' . $currency)) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_line_items" value="1">Save quantities</button></p>';
        echo '</form>';
    }
    echo '</div>';

    echo '<div class="np-oh-items-section">';
    echo '<div class="np-oh-two-col">';
    echo '<div>';
    echo '<h3>Shipping lines</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_shipping');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    if (empty($shipping_lines)) {
        echo '<p class="description">No shipping lines on this order.</p>';
    } else {
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>Title</th><th>Total</th><th>Remove</th></tr></thead><tbody>';
        foreach ($shipping_lines as $shipping_line) {
            if (!is_array($shipping_line)) {
                continue;
            }
            $shipping_id = isset($shipping_line['id']) ? (int) $shipping_line['id'] : 0;
            if ($shipping_id < 1) {
                continue;
            }
            echo '<tr>';
            echo '<td><input type="text" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][method_title]" value="' . esc_attr((string) ($shipping_line['method_title'] ?? '')) . '" class="regular-text" /></td>';
            echo '<td><input type="text" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][total]" value="' . esc_attr((string) ($shipping_line['total'] ?? '0')) . '" style="width:110px;" /></td>';
            echo '<td><label><input type="checkbox" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][remove]" value="1" /> Remove</label></td>';
            echo '<input type="hidden" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][method_id]" value="' . esc_attr((string) ($shipping_line['method_id'] ?? '')) . '" />';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '<h4>Add shipping line</h4>';
    echo '<div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
    echo '<div><label><strong>Title</strong><br /><input type="text" name="new_shipping[method_title]" class="regular-text" value="' . esc_attr((string) $new_shipping_form['method_title']) . '" /></label></div>';
    echo '<div><label><strong>Method ID</strong><br /><input type="text" name="new_shipping[method_id]" value="' . esc_attr((string) $new_shipping_form['method_id']) . '" style="width:140px;" /></label></div>';
    echo '<div><label><strong>Total</strong><br /><input type="text" name="new_shipping[total]" value="' . esc_attr((string) $new_shipping_form['total']) . '" style="width:110px;" /></label></div>';
    echo '</div>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_shipping" value="1">Save shipping</button></p>';
    echo '</form>';
    echo '</div>';

    echo '<div>';
    echo '<h3>Fees / discounts</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_fees');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    if (empty($fee_lines)) {
        echo '<p class="description">No fee lines on this order.</p>';
    } else {
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>Name</th><th>Amount</th><th>Remove</th></tr></thead><tbody>';
        foreach ($fee_lines as $fee_line) {
            if (!is_array($fee_line)) {
                continue;
            }
            $fee_id = isset($fee_line['id']) ? (int) $fee_line['id'] : 0;
            if ($fee_id < 1) {
                continue;
            }
            echo '<tr>';
            echo '<td><input type="text" name="fee_lines[' . esc_attr((string) $fee_id) . '][name]" class="regular-text" value="' . esc_attr((string) ($fee_line['name'] ?? '')) . '" /></td>';
            echo '<td><input type="text" name="fee_lines[' . esc_attr((string) $fee_id) . '][amount]" value="' . esc_attr((string) ($fee_line['total'] ?? '0')) . '" style="width:110px;" /></td>';
            echo '<td><label><input type="checkbox" name="fee_lines[' . esc_attr((string) $fee_id) . '][remove]" value="1" /> Remove</label></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '<h4>Add fee / discount</h4>';
    echo '<p class="description">Use a negative amount for a discount.</p>';
    echo '<div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
    echo '<div><label><strong>Name</strong><br /><input type="text" name="new_fee[name]" class="regular-text" value="' . esc_attr((string) $new_fee_form['name']) . '" /></label></div>';
    echo '<div><label><strong>Amount</strong><br /><input type="text" name="new_fee[amount]" value="' . esc_attr((string) $new_fee_form['amount']) . '" style="width:110px;" /></label></div>';
    echo '</div>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_fees" value="1">Save fees / discounts</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';
    echo '<form method="post" style="margin-top:12px;">';
    wp_nonce_field('np_order_hub_recalculate_order');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_recalculate_order" value="1">Recalculate totals</button>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    $help_scout_settings = np_order_hub_get_help_scout_settings();
    $help_scout_subject_default = 'Order ' . $order_label;
    $help_scout_subject_value = $help_scout_form['subject'] !== '' ? $help_scout_form['subject'] : $help_scout_subject_default;
    $help_scout_message_value = $help_scout_form['message'];
    $help_scout_status_value = $help_scout_form['status'] !== '' ? $help_scout_form['status'] : $help_scout_settings['default_status'];
    $help_scout_status_labels = array(
        'pending' => 'Pending',
        'active' => 'Active',
        'closed' => 'Closed',
    );
    if (!isset($help_scout_status_labels[$help_scout_status_value])) {
        $help_scout_status_value = $help_scout_settings['default_status'];
    }

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Help Scout</h2>';
    echo '<div class="inside">';
    if ($help_scout_settings['token'] === '' || empty($help_scout_settings['mailbox_id'])) {
        $settings_url = admin_url('admin.php?page=np-order-hub-help-scout');
        echo '<p class="description">Add a Help Scout API token and mailbox ID in <a href="' . esc_url($settings_url) . '">Help Scout settings</a>.</p>';
    } elseif ($help_scout_email === '') {
        echo '<p class="description">Customer email is missing on this order.</p>';
    } else {
        echo '<p><strong>Customer:</strong> ' . esc_html($help_scout_email) . '</p>';
        echo '<form method="post" style="max-width: 900px;">';
        wp_nonce_field('np_order_hub_help_scout_send');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="form-table">';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-subject">Subject</label></th>';
        echo '<td><input id="np-order-hub-help-scout-subject" name="help_scout_subject" type="text" class="regular-text" value="' . esc_attr($help_scout_subject_value) . '" /></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-status">Status</label></th>';
        echo '<td><select id="np-order-hub-help-scout-status" name="help_scout_status">';
        foreach ($help_scout_status_labels as $key => $label) {
            $selected = selected($help_scout_status_value, $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-message">Message</label></th>';
        echo '<td><textarea id="np-order-hub-help-scout-message" name="help_scout_message" rows="6" class="large-text">' . esc_textarea($help_scout_message_value) . '</textarea></td></tr>';
        echo '</table>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_help_scout_send" value="1">Send message</button></p>';
        echo '</form>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Reklamasjon</h2>';
    echo '<div class="inside">';
    $token_missing = np_order_hub_get_store_token($store) === '';
    if ($token_missing) {
        echo '<p>Store token missing in hub store settings.</p>';
    } elseif (empty($line_items)) {
        echo '<p>No line items found for this order.</p>';
    } else {
        echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
        echo '<input type="checkbox" id="np-order-hub-reklamasjon-toggle"' . ($reklamasjon_open ? ' checked' : '') . ' /> Reklamasjon';
        echo '</label>';
        echo '<div id="np-order-hub-reklamasjon-form" style="margin-top:12px;' . ($reklamasjon_open ? '' : ' display:none;') . '">';
        echo '<form method="post" style="max-width: 900px;">';
        wp_nonce_field('np_order_hub_create_reklamasjon');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th>Select</th>';
        echo '<th>Product</th>';
        echo '<th>Ordered Qty</th>';
        echo '<th>Claim Qty</th>';
        echo '<th>SKU</th>';
        echo '</tr></thead>';
        echo '<tbody>';
        foreach ($line_items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $item_id = isset($item['id']) ? (int) $item['id'] : 0;
            if ($item_id < 1) {
                continue;
            }
            $name = isset($item['name']) ? (string) $item['name'] : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $sku = isset($item['sku']) ? (string) $item['sku'] : '';
            $checked = in_array($item_id, $reklamasjon_selected_items, true) ? ' checked' : '';
            $qty_value = $qty;
            if (isset($reklamasjon_qty_input[$item_id])) {
                $posted_qty = absint($reklamasjon_qty_input[$item_id]);
                if ($posted_qty > 0) {
                    $qty_value = $posted_qty;
                }
            }

            echo '<tr>';
            echo '<td><input type="checkbox" name="reklamasjon_items[]" value="' . esc_attr((string) $item_id) . '"' . $checked . ' /></td>';
            echo '<td>' . esc_html($name !== '' ? $name : 'Item') . '</td>';
            echo '<td>' . esc_html((string) $qty) . '</td>';
            echo '<td><input type="number" name="reklamasjon_qty[' . esc_attr((string) $item_id) . ']" min="1" max="' . esc_attr((string) $qty) . '" value="' . esc_attr((string) $qty_value) . '" style="width:90px;" /></td>';
            echo '<td>' . esc_html($sku) . '</td>';
            echo '</tr>';
        }
        echo '</tbody>';
        echo '</table>';
        $allow_checked = $reklamasjon_allow_oos ? ' checked' : '';
        echo '<p style="margin-top:10px;">';
        echo '<label style="display:inline-flex; align-items:center; gap:6px;">';
        echo '<input type="checkbox" name="reklamasjon_allow_oos" value="1"' . $allow_checked . ' /> Create even if out of stock (customer waiting for stock)';
        echo '</label>';
        echo '</p>';
        if ($reklamasjon_popup_message !== '') {
            echo '<input type="hidden" id="np-order-hub-reklamasjon-popup" value="' . esc_attr($reklamasjon_popup_message) . '" />';
        }
        echo '<p style="margin-top:12px;">';
        echo '<button class="button button-primary" type="submit" name="np_order_hub_create_reklamasjon" value="1">Create claim order</button>';
        echo '</p>';
        echo '</form>';
        echo '</div>';
        echo '<script>
            document.addEventListener("DOMContentLoaded", function() {
                var toggle = document.getElementById("np-order-hub-reklamasjon-toggle");
                var form = document.getElementById("np-order-hub-reklamasjon-form");
                if (!toggle || !form) {
                    return;
                }
                toggle.addEventListener("change", function() {
                    form.style.display = toggle.checked ? "block" : "none";
                });
                var popup = document.getElementById("np-order-hub-reklamasjon-popup");
                if (popup && popup.value) {
                    var innerForm = form.querySelector("form");
                    var allow = innerForm ? innerForm.querySelector("input[name=\'reklamasjon_allow_oos\']") : null;
                    if (innerForm && (!allow || !allow.checked)) {
                        if (window.confirm(popup.value)) {
                            if (allow) {
                                allow.checked = true;
                            }
                            innerForm.submit();
                        }
                    }
                }
            });
        </script>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Items</h2>';
    echo '<div class="inside">';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Product</th>';
    echo '<th>Qty</th>';
    echo '<th>Line Total</th>';
    echo '<th>SKU</th>';
    echo '<th>Details</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($line_items)) {
        echo '<tr><td colspan="5">No line items found.</td></tr>';
    } else {
        foreach ($line_items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $name = isset($item['name']) ? (string) $item['name'] : '';
            $qty = isset($item['quantity']) ? (int) $item['quantity'] : 0;
            $line_total_raw = isset($item['total']) ? (string) $item['total'] : '0';
            $line_total = is_numeric($line_total_raw) ? (float) $line_total_raw : 0.0;
            $sku = isset($item['sku']) ? (string) $item['sku'] : '';
            $meta_lines = np_order_hub_format_meta_lines(isset($item['meta_data']) ? $item['meta_data'] : array());

            echo '<tr>';
            echo '<td>' . esc_html($name !== '' ? $name : 'Item') . '</td>';
            echo '<td>' . esc_html((string) $qty) . '</td>';
            echo '<td>' . esc_html(trim(number_format_i18n($line_total, 2) . ' ' . $currency)) . '</td>';
            echo '<td>' . esc_html($sku) . '</td>';
            if (!empty($meta_lines)) {
                echo '<td><ul style="margin:0; padding-left: 16px;">';
                foreach ($meta_lines as $line) {
                    echo '<li>' . esc_html($line) . '</li>';
                }
                echo '</ul></td>';
            } else {
                echo '<td></td>';
            }
            echo '</tr>';
        }
    }

    echo '</tbody>';
    echo '</table>';
    echo '</div>';
    echo '</div>';

    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}
