<?php
add_shortcode('np_order_hub_revenue_dashboard', 'np_order_hub_revenue_dashboard_shortcode');

add_filter('admin_body_class', 'np_order_hub_details_admin_body_class');

function np_order_hub_details_admin_body_class($classes) {
    $page = isset($_GET['page']) ? sanitize_key((string) wp_unslash($_GET['page'])) : '';
    if ($page !== 'np-order-hub-details') {
        return $classes;
    }
    $classes = trim((string) $classes);
    $classes .= ($classes !== '' ? ' ' : '') . 'np-oh-editor-screen-body';
    return $classes;
}

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
        'first_name' => 'Fornavn',
        'last_name' => 'Etternavn',
        'company' => 'Firma',
        'address_1' => 'Adresse 1',
        'address_2' => 'Adresse 2',
        'postcode' => 'Postnummer',
        'city' => 'Poststed',
        'state' => 'Fylke',
        'country' => 'Land',
    );
    if ($type === 'billing') {
        $fields['email'] = 'E-postadresse';
        $fields['phone'] = 'Telefon';
    } else {
        $fields['phone'] = 'Telefon';
    }

    echo '<div class="np-oh-address-fields">';
    foreach ($fields as $field => $label) {
        $field_id = 'np-order-hub-' . esc_attr($prefix . '-' . $field);
        $name = 'order_' . $prefix . '[' . $field . ']';
        $value = isset($values[$field]) ? (string) $values[$field] : '';
        echo '<label class="np-oh-field" for="' . $field_id . '">';
        echo '<span class="np-oh-field-label">' . esc_html($label) . '</span>';
        echo '<input id="' . $field_id . '" name="' . esc_attr($name) . '" type="text" class="np-oh-text-input" value="' . esc_attr($value) . '" />';
        echo '</label>';
    }
    echo '</div>';
}

function np_order_hub_selected_class_meta_keys() {
    return array(
        'selected_class',
        '_selected_class',
        'selected_class_name',
        'selected_class_value',
        'selected class',
        'selected class:',
        'klasse',
        'klasse:',
        'np_selected_class',
        '_np_selected_class',
        'school_class',
        'class_selection',
        '_class_selection',
        '_class',
        'class',
    );
}

function np_order_hub_normalize_selected_class_key($key) {
    $key = strtolower(trim(wp_strip_all_tags((string) $key)));
    $key = str_replace(array('-', ':', '  '), array('_', '', ' '), $key);
    $key = preg_replace('/\s+/', '_', $key);
    return is_string($key) ? $key : '';
}

function np_order_hub_is_selected_class_meta_key($key) {
    $normalized = np_order_hub_normalize_selected_class_key($key);
    if ($normalized === '') {
        return false;
    }

    $keys = array_map('np_order_hub_normalize_selected_class_key', np_order_hub_selected_class_meta_keys());
    return in_array($normalized, $keys, true);
}

function np_order_hub_extract_selected_class_from_value($value, $allow_unlabeled = false) {
    if (is_array($value)) {
        foreach ($value as $item) {
            $found = np_order_hub_extract_selected_class_from_value($item, $allow_unlabeled);
            if ($found !== '') {
                return $found;
            }
        }
        return '';
    }

    if (is_object($value)) {
        if (method_exists($value, 'get_data')) {
            return np_order_hub_extract_selected_class_from_value($value->get_data(), $allow_unlabeled);
        }
        return np_order_hub_extract_selected_class_from_value((array) $value, $allow_unlabeled);
    }

    if (!is_scalar($value)) {
        return '';
    }

    $text = trim(wp_strip_all_tags((string) $value));
    if ($text === '') {
        return '';
    }

    if (preg_match('/(?:selected\s*class|klasse)\s*:?\s*(.+)$/iu', $text, $matches)) {
        return sanitize_text_field(trim((string) $matches[1]));
    }

    return $allow_unlabeled ? sanitize_text_field($text) : '';
}

function np_order_hub_get_order_editor_selected_class($live_order) {
    $live_order = is_array($live_order) ? $live_order : array();

    $direct_keys = array(
        'selected_class',
        'selectedClass',
        'selected_class_name',
    );
    foreach ($direct_keys as $key) {
        if (!empty($live_order[$key])) {
            $selected_class = np_order_hub_extract_selected_class_from_value($live_order[$key], true);
            if ($selected_class !== '') {
                return $selected_class;
            }
        }
    }

    foreach ((array) ($live_order['meta_data'] ?? array()) as $meta) {
        if (!is_array($meta)) {
            continue;
        }
        $meta_key = (string) ($meta['display_key'] ?? $meta['key'] ?? '');
        $meta_value = $meta['display_value'] ?? $meta['value'] ?? '';
        if (np_order_hub_is_selected_class_meta_key($meta_key)) {
            $selected_class = np_order_hub_extract_selected_class_from_value($meta_value, true);
            if ($selected_class !== '') {
                return $selected_class;
            }
        }
        $selected_class = np_order_hub_extract_selected_class_from_value($meta_value, false);
        if ($selected_class !== '') {
            return $selected_class;
        }
    }

    foreach ((array) ($live_order['line_items'] ?? array()) as $item) {
        if (!is_array($item)) {
            continue;
        }
        foreach ((array) ($item['meta_data'] ?? array()) as $meta) {
            if (!is_array($meta)) {
                continue;
            }
            $meta_key = (string) ($meta['display_key'] ?? $meta['key'] ?? '');
            $meta_value = $meta['display_value'] ?? $meta['value'] ?? '';
            if (np_order_hub_is_selected_class_meta_key($meta_key)) {
                $selected_class = np_order_hub_extract_selected_class_from_value($meta_value, true);
                if ($selected_class !== '') {
                    return $selected_class;
                }
            }
            $selected_class = np_order_hub_extract_selected_class_from_value($meta_value, false);
            if ($selected_class !== '') {
                return $selected_class;
            }
        }
    }

    return '';
}

function np_order_hub_get_order_editor_address_summary_rows($values, $type) {
    $values = is_array($values) ? $values : array();
    $type = $type === 'shipping' ? 'shipping' : 'billing';
    $rows = array();

    $name = trim(
        trim((string) ($values['first_name'] ?? '')) . ' ' . trim((string) ($values['last_name'] ?? ''))
    );
    if ($name !== '') {
        $rows[] = array('label' => '', 'value' => $name);
    }

    $company = trim((string) ($values['company'] ?? ''));
    if ($company !== '' && $company !== $name) {
        $rows[] = array('label' => '', 'value' => $company);
    }

    foreach (array('address_1', 'address_2') as $field) {
        $line = trim((string) ($values[$field] ?? ''));
        if ($line !== '') {
            $rows[] = array('label' => '', 'value' => $line);
        }
    }

    $locality_parts = array();
    $postcode = trim((string) ($values['postcode'] ?? ''));
    $city = trim((string) ($values['city'] ?? ''));
    $state = trim((string) ($values['state'] ?? ''));
    if ($postcode !== '') {
        $locality_parts[] = $postcode;
    }
    if ($city !== '') {
        $locality_parts[] = $city;
    }
    $locality = trim(implode(' ', $locality_parts));
    if ($state !== '') {
        $locality = $locality !== '' ? ($locality . ', ' . $state) : $state;
    }
    if ($locality !== '') {
        $rows[] = array('label' => '', 'value' => $locality);
    }

    $country = trim((string) ($values['country'] ?? ''));
    if ($country !== '') {
        $rows[] = array('label' => '', 'value' => $country);
    }

    if ($type === 'billing') {
        $email = trim((string) ($values['email'] ?? ''));
        if ($email !== '') {
            $rows[] = array('label' => 'E-postadresse', 'value' => $email);
        }
    }

    $phone = trim((string) ($values['phone'] ?? ''));
    if ($phone !== '') {
        $rows[] = array('label' => 'Telefon', 'value' => $phone);
    }

    return $rows;
}

function np_order_hub_render_order_editor_address_panel($prefix, $values, $type) {
    $summary_rows = np_order_hub_get_order_editor_address_summary_rows($values, $type);

    echo '<div class="np-oh-address-card">';
    if (empty($summary_rows)) {
        echo '<p class="description">Ingen opplysninger lagret.</p>';
    } else {
        echo '<div class="np-oh-address-summary">';
        foreach ($summary_rows as $row) {
            $label = (string) ($row['label'] ?? '');
            $value = (string) ($row['value'] ?? '');
            if ($value === '') {
                continue;
            }
            echo '<p>';
            if ($label !== '') {
                echo '<strong>' . esc_html($label) . ':</strong> ';
            }
            echo esc_html($value);
            echo '</p>';
        }
        echo '</div>';
    }

    echo '<details class="np-oh-address-edit">';
    echo '<summary>Rediger</summary>';
    np_order_hub_render_order_editor_address_fields($prefix, $values, $type);
    echo '</details>';
    echo '</div>';
}

function np_order_hub_render_order_editor_notes_list($notes) {
    $notes = is_array($notes) ? $notes : array();
    if (empty($notes)) {
        echo '<p class="description">Ingen nylige ordrenotater funnet.</p>';
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
        $type = !empty($note['is_customer_note']) ? 'Kundenotat' : 'Internt notat';
        $author = trim((string) ($note['added_by'] ?? ''));
        if ($author === '') {
            $author = !empty($note['added_by_user']) ? 'Bruker' : 'System';
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
        .np-oh-editor-screen.wrap{max-width:1440px}
        .np-oh-editor-screen .np-oh-poststuff{padding-top:0}
        .np-oh-editor-screen .wp-heading-inline{margin-bottom:6px}
        .np-oh-editor-screen .np-oh-order-header-meta{margin:8px 0 18px;color:#50575e;font-size:14px}
        body.np-oh-editor-screen-body #post-body,
        body.np-oh-editor-screen-body #post-body.metabox-holder,
        body.np-oh-editor-screen-body #post-body.metabox-holder.columns-2{
            margin:0!important;
            margin-right:0!important;
            padding:0!important;
            max-width:none!important;
            display:block!important;
            min-width:0!important;
        }
        body.np-oh-editor-screen-body #post-body-content,
        body.np-oh-editor-screen-body #side-sortables,
        body.np-oh-editor-screen-body #normal-sortables,
        body.np-oh-editor-screen-body #postbox-container-1,
        body.np-oh-editor-screen-body #postbox-container-2{
            margin:0!important;
            float:none!important;
            width:auto!important;
            max-width:none!important;
            min-width:0!important;
        }
        .np-oh-editor-screen .np-oh-layout{display:grid;grid-template-columns:minmax(0,1fr) 280px;grid-template-areas:"main sidebar";gap:20px;margin:0!important;align-items:start}
        .np-oh-editor-screen .np-oh-sidebar-column,
        .np-oh-editor-screen .np-oh-main-column{float:none!important;width:auto!important;margin:0!important}
        .np-oh-editor-screen .np-oh-sidebar-column{grid-area:sidebar;width:280px!important;max-width:280px;min-width:0}
        .np-oh-editor-screen .np-oh-main-column{grid-area:main;min-width:0}
        .np-oh-editor-screen .np-oh-sidebar-actions{width:100%}
        .np-oh-editor-screen .postbox{margin:0 0 16px;border:1px solid #dcdcde;box-shadow:none}
        .np-oh-editor-screen .postbox .hndle{margin:0;padding:11px 12px;border-bottom:1px solid #ccd0d4;font-size:13px;font-weight:600}
        .np-oh-editor-screen .inside{margin:0;padding:12px}
        .np-oh-editor-screen .order_data_column_container{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}
        .np-oh-editor-screen .order_data_column h3,
        .np-oh-editor-screen .np-oh-items-section h3,
        .np-oh-editor-screen .np-oh-notes-grid h3{margin:0 0 12px;padding-bottom:8px;border-bottom:1px solid #eee;font-size:13px}
        .np-oh-editor-screen .np-oh-readonly-list p{margin:0 0 8px}
        .np-oh-editor-screen .np-oh-readonly-list p:last-child{margin-bottom:0}
        .np-oh-editor-screen .np-oh-summary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 16px}
        .np-oh-editor-screen .np-oh-summary-grid p{margin:0}
        .np-oh-editor-screen .np-oh-two-col{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
        .np-oh-editor-screen .np-oh-item-summary{display:flex;gap:12px;align-items:flex-start}
        .np-oh-editor-screen .np-oh-item-thumb img{display:block;width:60px;height:60px;object-fit:cover;border:1px solid #ccd0d4;border-radius:2px;background:#fff}
        .np-oh-editor-screen .np-oh-item-title{display:block;margin-bottom:6px;font-size:16px;line-height:1.35;color:#2271b1}
        .np-oh-editor-screen .np-oh-item-detail{margin:0 0 6px;color:#1d2327}
        .np-oh-editor-screen .np-oh-item-detail strong{font-weight:600;color:#50575e}
        .np-oh-editor-screen .np-oh-item-meta{margin:8px 0 0 0;padding:0;list-style:none}
        .np-oh-editor-screen .np-oh-item-meta li{margin:0 0 5px;color:#1d2327}
        .np-oh-editor-screen .np-oh-item-editor{display:grid;gap:6px;max-width:360px;margin-top:12px}
        .np-oh-editor-screen .np-oh-item-editor label{font-size:12px;font-weight:600;color:#50575e}
        .np-oh-editor-screen .np-oh-item-editor-static{padding:8px 10px;background:#f6f7f7;border:1px solid #dcdcde;border-radius:4px}
        .np-oh-editor-screen .np-oh-item-remove{margin-top:8px}
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
        .np-oh-editor-screen .np-oh-woo-items-table th{font-weight:500;color:#646970}
        .np-oh-editor-screen .np-oh-woo-items-table td{padding-top:18px;padding-bottom:18px}
        .np-oh-editor-screen .np-oh-charge-lines{margin-top:12px;border-top:1px solid #dcdcde}
        .np-oh-editor-screen .np-oh-charge-line{display:flex;justify-content:space-between;gap:16px;padding:16px 0;border-bottom:1px solid #f0f0f1}
        .np-oh-editor-screen .np-oh-charge-line-title{font-weight:600}
        .np-oh-editor-screen .np-oh-charge-line-meta{display:block;margin-top:6px;color:#646970}
        .np-oh-editor-screen .np-oh-order-totals-wrap{display:flex;justify-content:flex-end;margin-top:18px}
        .np-oh-editor-screen .np-oh-order-totals{width:100%;max-width:360px;border-top:2px solid #dcdcde;padding-top:10px}
        .np-oh-editor-screen .np-oh-order-total-row{display:flex;justify-content:space-between;gap:18px;padding:6px 0}
        .np-oh-editor-screen .np-oh-order-total-row strong{font-weight:600}
        .np-oh-editor-screen .np-oh-order-total-row.is-paid{border-top:1px solid #dcdcde;margin-top:6px;padding-top:10px}
        .np-oh-editor-screen .np-oh-payment-note{margin:10px 0 0;color:#50575e;text-align:right}
        .np-oh-editor-screen .np-oh-advanced-edit{margin-top:18px;border-top:1px solid #dcdcde;padding-top:16px}
        .np-oh-editor-screen .np-oh-advanced-edit summary{cursor:pointer;font-weight:600}
        .np-oh-editor-screen .np-oh-add-item-panel{margin-top:18px;padding-top:18px;border-top:1px solid #dcdcde}
        .np-oh-editor-screen .np-oh-add-item-grid{display:grid;grid-template-columns:minmax(0,1fr) 110px auto;gap:12px;align-items:end}
        .np-oh-editor-screen .np-oh-add-item-grid .button{margin-bottom:0}
        .np-oh-editor-screen .np-oh-search-results{margin-top:12px}
        .np-oh-editor-screen .np-oh-search-results select{max-width:none}
        .np-oh-editor-screen .np-oh-sidebar-form + .np-oh-sidebar-form{margin-top:14px;padding-top:14px;border-top:1px solid #eee}
        .np-oh-editor-screen .np-oh-sidebar-actions .button{margin:0 8px 8px 0}
        .np-oh-editor-screen .np-oh-sidebar-actions select,
        .np-oh-editor-screen .np-oh-sidebar-actions input[type=text]{width:100%}
        .np-oh-editor-screen .np-oh-address-card{display:flex;flex-direction:column;gap:12px}
        .np-oh-editor-screen .np-oh-address-summary{min-height:132px;padding:14px;border:1px solid #dcdcde;background:#fff}
        .np-oh-editor-screen .np-oh-address-summary p{margin:0 0 6px;line-height:1.5}
        .np-oh-editor-screen .np-oh-address-summary p:last-child{margin-bottom:0}
        .np-oh-editor-screen .np-oh-address-edit{border-top:1px solid #eee;padding-top:10px}
        .np-oh-editor-screen .np-oh-address-edit summary{cursor:pointer;font-weight:600;color:#2271b1}
        .np-oh-editor-screen .np-oh-address-edit[open] summary{margin-bottom:12px}
        .np-oh-editor-screen .np-oh-address-fields{display:grid;gap:12px}
        .np-oh-editor-screen .np-oh-field{display:block}
        .np-oh-editor-screen .np-oh-field-label{display:block;margin-bottom:6px;font-size:12px;font-weight:600;color:#50575e}
        .np-oh-editor-screen .np-oh-text-input,
        .np-oh-editor-screen .regular-text,
        .np-oh-editor-screen .large-text,
        .np-oh-editor-screen textarea,
        .np-oh-editor-screen select{width:100%;max-width:100%}
        .np-oh-editor-screen .np-oh-meta-list{margin:0}
        .np-oh-editor-screen .np-oh-meta-list dt{font-weight:600;margin:0 0 4px}
        .np-oh-editor-screen .np-oh-meta-list dd{margin:0 0 12px}
        .np-oh-editor-screen .np-oh-panel-actions .button-link-delete{padding:0}
        .np-oh-editor-screen .form-table th{width:120px;padding-left:0}
        .np-oh-editor-screen .form-table td{padding-right:0}
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
            .np-oh-editor-screen .np-oh-layout{grid-template-columns:1fr;grid-template-areas:"sidebar" "main"}
            .np-oh-editor-screen .np-oh-sidebar-column,
            .np-oh-editor-screen .np-oh-main-column{grid-column:auto;width:100%!important;max-width:none}
        }
        @media (max-width: 960px){
            .np-oh-editor-screen .order_data_column_container{grid-template-columns:1fr}
        }
        @media (max-width: 860px){
            .np-oh-editor-screen .np-oh-two-col{grid-template-columns:1fr}
            .np-oh-editor-screen .np-oh-add-item-grid{grid-template-columns:1fr}
        }
    </style>';
}

function np_order_hub_get_order_editor_item_meta_map($item) {
    $map = array();
    $meta_data = isset($item['meta_data']) && is_array($item['meta_data']) ? $item['meta_data'] : array();
    foreach ($meta_data as $meta) {
        if (!is_array($meta)) {
            continue;
        }
        $key = trim((string) ($meta['display_key'] ?? $meta['key'] ?? ''));
        if ($key === '' || strpos($key, '_') === 0) {
            continue;
        }
        $value = $meta['display_value'] ?? $meta['value'] ?? '';
        if (is_array($value) || is_object($value)) {
            $value = wp_json_encode($value);
        }
        $value = trim((string) $value);
        if ($value === '') {
            continue;
        }
        $map[$key] = wp_strip_all_tags($value);
    }
    return $map;
}

function np_order_hub_get_order_editor_customer_label($live_order) {
    $customer_id = is_array($live_order) ? absint($live_order['customer_id'] ?? 0) : 0;
    if ($customer_id > 0) {
        return '#' . $customer_id;
    }
    return 'Gjest';
}

function np_order_hub_get_order_editor_status_label($status, $allowed_statuses = array()) {
    $status = sanitize_key((string) $status);
    if ($status !== '' && isset($allowed_statuses[$status])) {
        return (string) $allowed_statuses[$status];
    }
    return $status !== '' ? ucwords(str_replace('-', ' ', $status)) : '—';
}

function np_order_hub_render_order_editor_totals_summary($live_order, $currency) {
    $live_order = is_array($live_order) ? $live_order : array();
    $currency = (string) $currency;
    $items_subtotal = 0.0;
    foreach ((array) ($live_order['line_items'] ?? array()) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $value = np_order_hub_parse_numeric_value($item['subtotal'] ?? $item['total'] ?? null);
        $items_subtotal += $value !== null ? (float) $value : 0.0;
    }

    $shipping_total = np_order_hub_parse_numeric_value($live_order['shipping_total'] ?? null);
    $discount_total = np_order_hub_parse_numeric_value($live_order['discount_total'] ?? null);
    $total_tax = np_order_hub_parse_numeric_value($live_order['total_tax'] ?? null);
    $grand_total = np_order_hub_parse_numeric_value($live_order['total'] ?? null);
    $date_paid_gmt = np_order_hub_parse_datetime_gmt($live_order['date_paid_gmt'] ?? '', $live_order['date_paid'] ?? '');
    $date_paid_label = $date_paid_gmt !== '' ? get_date_from_gmt($date_paid_gmt, 'd.m.Y \\k\\l H:i') : '';
    $payment_method_title = trim((string) ($live_order['payment_method_title'] ?? ''));

    echo '<div class="np-oh-order-totals-wrap">';
    echo '<div class="np-oh-order-totals">';
    echo '<div class="np-oh-order-total-row"><span>Produktsum:</span><strong>' . esc_html(np_order_hub_format_money($items_subtotal, $currency)) . '</strong></div>';
    echo '<div class="np-oh-order-total-row"><span>Frakt:</span><strong>' . esc_html(np_order_hub_format_money($shipping_total !== null ? $shipping_total : 0, $currency)) . '</strong></div>';
    if ($discount_total !== null && abs($discount_total) > 0.0001) {
        echo '<div class="np-oh-order-total-row"><span>Rabatt:</span><strong>-' . esc_html(np_order_hub_format_money(abs($discount_total), $currency)) . '</strong></div>';
    }
    if ($total_tax !== null && abs($total_tax) > 0.0001) {
        echo '<div class="np-oh-order-total-row"><span>MVA:</span><strong>' . esc_html(np_order_hub_format_money($total_tax, $currency)) . '</strong></div>';
    }
    echo '<div class="np-oh-order-total-row"><span>Ordretotal:</span><strong>' . esc_html(np_order_hub_format_money($grand_total !== null ? $grand_total : 0, $currency)) . '</strong></div>';
    echo '<div class="np-oh-order-total-row is-paid"><span>Betalt:</span><strong>' . esc_html(np_order_hub_format_money($grand_total !== null ? $grand_total : 0, $currency)) . '</strong></div>';
    if ($date_paid_label !== '' || $payment_method_title !== '') {
        $payment_bits = array();
        if ($date_paid_label !== '') {
            $payment_bits[] = $date_paid_label;
        }
        if ($payment_method_title !== '') {
            $payment_bits[] = 'via ' . $payment_method_title;
        }
        echo '<p class="np-oh-payment-note">' . esc_html(implode(' ', $payment_bits)) . '</p>';
    }
    echo '</div>';
    echo '</div>';
}

function np_order_hub_render_order_editor_item_summary($item) {
    $item = is_array($item) ? $item : array();
    $name = isset($item['name']) ? (string) $item['name'] : 'Item';
    $sku = trim((string) ($item['sku'] ?? ''));
    $parent_name = trim((string) ($item['parent_name'] ?? ''));
    $variation_id = absint($item['variation_id'] ?? 0);
    $image_src = '';
    if (!empty($item['image']) && is_array($item['image']) && !empty($item['image']['src'])) {
        $image_src = esc_url((string) $item['image']['src']);
    }
    $meta_map = np_order_hub_get_order_editor_item_meta_map($item);
    $title = $parent_name !== '' ? $parent_name : $name;

    echo '<div class="np-oh-item-summary">';
    if ($image_src !== '') {
        echo '<div class="np-oh-item-thumb"><img src="' . $image_src . '" alt="" /></div>';
    }
    echo '<div class="np-oh-item-copy">';
    echo '<span class="np-oh-item-title">' . esc_html($title) . '</span>';
    if ($sku !== '') {
        echo '<div class="np-oh-item-detail"><strong>Produktnummer:</strong> ' . esc_html($sku) . '</div>';
    }
    if ($variation_id > 0) {
        echo '<div class="np-oh-item-detail"><strong>Variant-ID:</strong> ' . esc_html((string) $variation_id) . '</div>';
    }
    if (!empty($meta_map)) {
        echo '<ul class="np-oh-item-meta">';
        foreach ($meta_map as $meta_key => $meta_value) {
            echo '<li><strong>' . esc_html($meta_key) . ':</strong> ' . esc_html($meta_value) . '</li>';
        }
        echo '</ul>';
    }
    echo '</div>';
    echo '</div>';
}

function np_order_hub_encode_order_editor_option_value($product_id, $variation_id) {
    return absint($product_id) . ':' . absint($variation_id);
}

function np_order_hub_decode_order_editor_option_value($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return array('product_id' => 0, 'variation_id' => 0);
    }

    $parts = array_map('trim', explode(':', $value, 2));
    return array(
        'product_id' => isset($parts[0]) ? absint($parts[0]) : 0,
        'variation_id' => isset($parts[1]) ? absint($parts[1]) : 0,
    );
}

function np_order_hub_get_order_editor_item_options($item) {
    $options = array();
    $raw_options = isset($item['editor_options']) && is_array($item['editor_options']) ? $item['editor_options'] : array();
    foreach ($raw_options as $option) {
        if (!is_array($option)) {
            continue;
        }
        $product_id = absint($option['product_id'] ?? 0);
        $variation_id = absint($option['variation_id'] ?? 0);
        $label = trim((string) ($option['label'] ?? ''));
        if ($product_id < 1 || $label === '') {
            continue;
        }
        $options[] = array(
            'product_id' => $product_id,
            'variation_id' => $variation_id,
            'label' => $label,
        );
    }

    if (empty($options)) {
        $product_id = absint($item['product_id'] ?? 0);
        $variation_id = absint($item['variation_id'] ?? 0);
        if ($product_id > 0) {
            $options[] = array(
                'product_id' => $product_id,
                'variation_id' => $variation_id,
                'label' => trim((string) ($item['name'] ?? 'Varelinje')),
            );
        }
    }

    return $options;
}

function np_order_hub_render_order_editor_item_selector($item, $item_id) {
    $item = is_array($item) ? $item : array();
    $item_id = absint($item_id);
    if ($item_id < 1) {
        return;
    }

    $options = np_order_hub_get_order_editor_item_options($item);
    if (empty($options)) {
        return;
    }

    $current_value = np_order_hub_encode_order_editor_option_value(
        absint($item['product_id'] ?? 0),
        absint($item['variation_id'] ?? 0)
    );

    echo '<div class="np-oh-item-editor">';
    echo '<label for="np-oh-item-selection-' . esc_attr((string) $item_id) . '">Variant / størrelse</label>';
    if (count($options) === 1) {
        echo '<div class="np-oh-item-editor-static">' . esc_html((string) $options[0]['label']) . '</div>';
        echo '<input type="hidden" name="line_items[' . esc_attr((string) $item_id) . '][editor_selection]" value="' . esc_attr(np_order_hub_encode_order_editor_option_value($options[0]['product_id'], $options[0]['variation_id'])) . '" />';
    } else {
        echo '<select id="np-oh-item-selection-' . esc_attr((string) $item_id) . '" name="line_items[' . esc_attr((string) $item_id) . '][editor_selection]">';
        foreach ($options as $option) {
            $value = np_order_hub_encode_order_editor_option_value($option['product_id'], $option['variation_id']);
            echo '<option value="' . esc_attr($value) . '"' . selected($current_value, $value, false) . '>' . esc_html((string) $option['label']) . '</option>';
        }
        echo '</select>';
    }
    echo '<label class="np-oh-item-remove"><input type="checkbox" name="line_items[' . esc_attr((string) $item_id) . '][remove]" value="1" /> Fjern varelinje</label>';
    echo '</div>';
}

function np_order_hub_format_order_editor_search_result_label($result, $currency) {
    $result = is_array($result) ? $result : array();
    $label = trim((string) ($result['label'] ?? 'Produkt'));
    $price_value = np_order_hub_parse_numeric_value($result['price'] ?? null);
    if ($price_value !== null) {
        $label .= ' — ' . np_order_hub_format_money($price_value, $currency);
    }
    $stock_status = trim((string) ($result['stock_status'] ?? ''));
    if ($stock_status !== '') {
        $label .= ' [' . $stock_status . ']';
    }
    return $label;
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
    $item_search_query = '';
    $item_search_results = array();
    $new_item_form = array(
        'selection' => '',
        'quantity' => '1',
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
            $help_scout_notice = array('type' => 'error', 'message' => 'Kunde-e-post mangler på denne ordren.', 'allow_html' => false);
        } elseif ($help_scout_form['subject'] === '' || $help_scout_form['message'] === '') {
            $help_scout_notice = array('type' => 'error', 'message' => 'Emne og melding er påkrevd.', 'allow_html' => false);
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

    if ($record && !empty($_POST['np_order_hub_search_line_items'])) {
        check_admin_referer('np_order_hub_search_line_items');
        $item_search_query = sanitize_text_field((string) ($_POST['item_search_query'] ?? ''));
        $new_item_form['selection'] = sanitize_text_field((string) ($_POST['new_item']['selection'] ?? ''));
        $new_item_form['quantity'] = (string) max(1, absint($_POST['new_item']['quantity'] ?? 1));
        if ($item_search_query === '' || strlen($item_search_query) < 2) {
            $live_order_notice = array('type' => 'error', 'message' => 'Skriv minst to tegn for å søke etter produkter.');
        } else {
            $result = np_order_hub_search_remote_order_products($store, $item_search_query, 25);
            if (is_wp_error($result)) {
                $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
            } else {
                $item_search_results = isset($result['results']) && is_array($result['results']) ? $result['results'] : array();
                if (empty($item_search_results)) {
                    $live_order_notice = array('type' => 'error', 'message' => 'Fant ingen produkter for søket.');
                }
            }
        }
    }

    if ($record && !empty($_POST['np_order_hub_add_line_item'])) {
        check_admin_referer('np_order_hub_search_line_items');
        $item_search_query = sanitize_text_field((string) ($_POST['item_search_query'] ?? ''));
        $new_item_form['selection'] = sanitize_text_field((string) ($_POST['new_item']['selection'] ?? ''));
        $new_item_form['quantity'] = (string) max(1, absint($_POST['new_item']['quantity'] ?? 1));
        $selection = np_order_hub_decode_order_editor_option_value($new_item_form['selection']);
        if (($selection['product_id'] ?? 0) < 1) {
            $live_order_notice = array('type' => 'error', 'message' => 'Velg et produkt som skal legges til.');
        } else {
            $result = np_order_hub_update_remote_order_items(
                $store,
                (int) $record['order_id'],
                array(),
                array(
                    array(
                        'product_id' => (int) $selection['product_id'],
                        'variation_id' => (int) ($selection['variation_id'] ?? 0),
                        'quantity' => max(1, absint($new_item_form['quantity'])),
                    ),
                )
            );
            if (is_wp_error($result)) {
                $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
            } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
                $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
                $live_order_notice = array('type' => 'success', 'message' => 'Produkt lagt til på ordren.');
                $item_search_query = '';
                $item_search_results = array();
                $new_item_form = array('selection' => '', 'quantity' => '1');
            }
        }

        if ($item_search_query !== '' && empty($item_search_results)) {
            $search_result = np_order_hub_search_remote_order_products($store, $item_search_query, 25);
            if (!is_wp_error($search_result)) {
                $item_search_results = isset($search_result['results']) && is_array($search_result['results']) ? $search_result['results'] : array();
            }
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
            $selection = np_order_hub_decode_order_editor_option_value($item_row['editor_selection'] ?? '');
            $items_payload[] = array(
                'item_id' => absint($item_id),
                'quantity' => absint($item_row['quantity'] ?? 0),
                'product_id' => (int) ($selection['product_id'] ?? 0),
                'variation_id' => (int) ($selection['variation_id'] ?? 0),
                'remove' => !empty($item_row['remove']) ? 1 : 0,
            );
        }
        $result = np_order_hub_update_remote_order_items($store, (int) $record['order_id'], $items_payload);
        if (is_wp_error($result)) {
            $live_order_notice = array('type' => 'error', 'message' => $result->get_error_message());
        } elseif (is_array($result) && !empty($result['order']) && is_array($result['order'])) {
            $record = np_order_hub_upsert_record_from_remote_payload($record, $store, $result['order']);
            $live_order_notice = array('type' => 'success', 'message' => 'Varelinjer oppdatert.');
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
            $reklamasjon_notice = array('type' => 'error', 'message' => 'Ingen varelinjer funnet for denne ordren.', 'allow_html' => false);
        } elseif (empty($selected_items)) {
            $reklamasjon_notice = array('type' => 'error', 'message' => 'Velg minst én varelinje for reklamasjonsordren.', 'allow_html' => false);
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
                    $errors[] = 'Valgt varelinje ble ikke funnet.';
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
        echo '<div class="error"><p>Ordren ble ikke funnet.</p></div>';
        echo '</div>';
        return;
    }

    $order_label = $record['order_number'] !== '' ? ('#' . $record['order_number']) : ('#' . $record['order_id']);
    $date_label = '';
    if (!empty($record['date_created_gmt']) && $record['date_created_gmt'] !== '0000-00-00 00:00:00') {
        $date_label = get_date_from_gmt($record['date_created_gmt'], 'd.m.y');
    }
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
    $customer_ip_address = trim((string) ($live_order['customer_ip_address'] ?? ''));
    $date_paid_label = '';
    $date_paid_gmt = np_order_hub_parse_datetime_gmt($live_order['date_paid_gmt'] ?? '', $live_order['date_paid'] ?? '');
    if ($date_paid_gmt !== '') {
        $date_paid_label = get_date_from_gmt($date_paid_gmt, 'd.m.Y \\k\\l H:i');
    }
    $status_label = np_order_hub_get_order_editor_status_label($record['status'] ?? '', $allowed_statuses);
    $customer_label = np_order_hub_get_order_editor_customer_label($live_order);
    $selected_class = np_order_hub_get_order_editor_selected_class($live_order);
    $linked_cases = np_order_hub_help_scout_get_cases_for_record((int) $record['id']);
    $header_bits = array();
    if ($payment_method_title !== '') {
        $header_bits[] = 'Betaling via ' . $payment_method_title . ($transaction_id !== '' ? ' (' . $transaction_id . ')' : '');
    }
    if ($date_paid_label !== '') {
        $header_bits[] = 'Betalt ' . $date_paid_label;
    }
    if ($customer_ip_address !== '') {
        $header_bits[] = 'Kunde-IP: ' . $customer_ip_address;
    }

    np_order_hub_render_order_editor_styles();
    echo '<h1 class="wp-heading-inline">Ordre nr. ' . esc_html(ltrim($order_label, '#')) . ' – Detaljer</h1>';
    echo '<a class="page-title-action" href="' . esc_url(admin_url('admin.php?page=np-order-hub')) . '">Tilbake til hub</a>';
    if (!empty($header_bits)) {
        echo '<p class="np-oh-order-header-meta">' . esc_html(implode('. ', $header_bits)) . '</p>';
    }
    echo '<div class="np-oh-poststuff">';
    echo '<div class="np-oh-layout">';
    echo '<div class="np-oh-sidebar-column">';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Handlinger</h2>';
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
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_status" value="1">Oppdater</button></p>';
        if ($token_missing) {
            echo '<p class="description">Butikktoken mangler i hub-innstillingene.</p>';
        }
        echo '</form>';
    }

    echo '<form class="np-oh-sidebar-form" method="post">';
    wp_nonce_field('np_order_hub_update_delivery_bucket');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<p><label for="np-order-hub-delivery-bucket"><strong>Leveringsbøtte</strong></label></p>';
    echo '<select name="delivery_bucket" id="np-order-hub-delivery-bucket">';
    echo '<option value="standard"' . selected($delivery_bucket, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_delivery_bucket" value="1">Oppdater</button></p>';
    echo '</form>';

    echo '<form class="np-oh-sidebar-form" method="post">';
    wp_nonce_field('np_order_hub_send_order_email');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<p><label for="np-order-hub-email-action"><strong>Woo e-post</strong></label></p>';
    echo '<select name="order_email_action" id="np-order-hub-email-action">';
    foreach ($email_actions as $action_key => $action_label) {
        echo '<option value="' . esc_attr((string) $action_key) . '"' . selected($order_email_action_value, (string) $action_key, false) . '>' . esc_html((string) $action_label) . '</option>';
    }
    echo '</select>';
    echo '<p><button class="button" type="submit" name="np_order_hub_send_order_email" value="1">Send e-post</button></p>';
    echo '</form>';

    echo '<div class="np-oh-sidebar-form">';
    if ($packing_url !== '') {
        echo '<a class="button" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Pakkseddel</a>';
    }
    if ($open_order_url !== '') {
        echo '<a class="button button-primary" href="' . esc_url($open_order_url) . '" target="_blank" rel="noopener">Åpne i butikk</a>';
    }
    echo '<form method="post" style="margin-top:8px;">';
    wp_nonce_field('np_order_hub_refresh_live_order');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_refresh_live_order" value="1">Oppdater live-data</button>';
    echo '</form>';
    echo '<form method="post" style="margin-top:8px;">';
    wp_nonce_field('np_order_hub_delete_record');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button-link-delete" type="submit" name="np_order_hub_delete_record" value="1" onclick="return confirm(\'Slette denne ordren fra huben?\');">Slett fra hub</button>';
    echo '</form>';
    echo '</div>';
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
    echo '<h2 class="hndle">Kundenotat</h2>';
    echo '<div class="inside">';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_customer_note');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<textarea name="customer_note" rows="5" class="large-text">' . esc_textarea($customer_note_value) . '</textarea>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_customer_note" value="1">Lagre kundenotat</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Ordrenotater</h2>';
    echo '<div class="inside">';
    echo '<h3>Legg til notat</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_add_order_note');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<textarea name="order_note" rows="5" class="large-text">' . esc_textarea($order_note_form_value) . '</textarea>';
    echo '<p><button class="button" type="submit" name="np_order_hub_add_order_note" value="1">Legg til notat</button></p>';
    echo '</form>';
    echo '<h3 style="margin-top:24px;">Siste notater</h3>';
    np_order_hub_render_order_editor_notes_list($order_notes);
    echo '</div>';
    echo '</div>';

    echo '</div>';

    echo '<div class="np-oh-main-column">';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Ordredata</h2>';
    echo '<div class="inside">';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_addresses');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<div class="order_data_column_container">';
    echo '<div class="order_data_column">';
    echo '<h3>Generelt</h3>';
    echo '<div class="np-oh-readonly-list np-oh-summary-grid">';
    echo '<p><strong>Ordre:</strong> ' . esc_html($order_label) . '</p>';
    echo '<p><strong>Status:</strong> ' . esc_html($status_label) . '</p>';
    echo '<p><strong>Kunde:</strong> ' . esc_html($customer_label) . '</p>';
    echo '<p><strong>Butikk:</strong> ' . esc_html($record['store_name']) . '</p>';
    if ($date_label !== '') {
        echo '<p><strong>Dato opprettet:</strong> ' . esc_html($date_label) . '</p>';
    }
    if ($modified_label !== '') {
        echo '<p><strong>Live synket:</strong> ' . esc_html($modified_label) . '</p>';
    }
    echo '<p><strong>Totalt:</strong> ' . esc_html($total_display) . '</p>';
    echo '<p><strong>Betalingsmetode:</strong> ' . esc_html($payment_method_title !== '' ? $payment_method_title : '—') . '</p>';
    if ($transaction_id !== '') {
        echo '<p><strong>Transaksjons-ID:</strong> ' . esc_html($transaction_id) . '</p>';
    }
    if ($customer_ip_address !== '') {
        echo '<p><strong>Kunde-IP:</strong> ' . esc_html($customer_ip_address) . '</p>';
    }
    if ($created_via !== '') {
        echo '<p><strong>Opprettet via:</strong> ' . esc_html($created_via) . '</p>';
    }
    if ($selected_class !== '') {
        echo '<p><strong>Selected Class:</strong> ' . esc_html($selected_class) . '</p>';
    }
    echo '</div>';
    echo '</div>';
    echo '<div class="order_data_column">';
    echo '<h3>Fakturering</h3>';
    np_order_hub_render_order_editor_address_panel('billing', $live_billing, 'billing');
    echo '</div>';
    echo '<div class="order_data_column">';
    echo '<h3>Frakt</h3>';
    np_order_hub_render_order_editor_address_panel('shipping', $live_shipping, 'shipping');
    echo '</div>';
    echo '</div>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_addresses" value="1">Lagre ordredata</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Produktlinjer</h2>';
    echo '<div class="inside">';
    echo '<p class="description">Du kan endre variant / størrelse, justere antall, fjerne varelinjer og legge til nye produkter direkte fra huben.</p>';
    echo '<div class="np-oh-items-section">';
    if (empty($line_items)) {
        echo '<p class="description">Ingen varelinjer funnet.</p>';
    } else {
        echo '<form method="post">';
        wp_nonce_field('np_order_hub_update_line_items');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="widefat striped np-oh-items-table np-oh-woo-items-table">';
        echo '<thead><tr><th>Produkt</th><th class="column-cost np-oh-amount">Pris</th><th class="column-qty">Antall</th><th class="column-total np-oh-amount">Totalt</th></tr></thead><tbody>';
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
            np_order_hub_render_order_editor_item_selector($item, $item_id);
            echo '</td>';
            echo '<td class="np-oh-amount">' . esc_html(np_order_hub_format_money($unit_cost, $currency)) . '</td>';
            echo '<td><input class="np-oh-qty-input" type="number" min="1" name="line_items[' . esc_attr((string) $item_id) . '][quantity]" value="' . esc_attr((string) max(1, $qty)) . '" /></td>';
            echo '<td class="np-oh-amount">' . esc_html(np_order_hub_format_money($total_value, $currency)) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_update_line_items" value="1">Lagre varelinjer</button></p>';
        echo '</form>';
    }
    echo '</div>';
    echo '<div class="np-oh-add-item-panel">';
    echo '<h3>Legg til produkt</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_search_line_items');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<div class="np-oh-add-item-grid">';
    echo '<div><label class="np-oh-field"><span class="np-oh-field-label">Søk etter produkt eller variant</span><input type="text" name="item_search_query" class="regular-text" value="' . esc_attr($item_search_query) . '" /></label></div>';
    echo '<div><label class="np-oh-field"><span class="np-oh-field-label">Antall</span><input type="number" min="1" name="new_item[quantity]" value="' . esc_attr((string) $new_item_form['quantity']) . '" /></label></div>';
    echo '<div><button class="button" type="submit" name="np_order_hub_search_line_items" value="1">Søk</button></div>';
    echo '</div>';
    if (!empty($item_search_results)) {
        echo '<div class="np-oh-search-results">';
        echo '<label class="np-oh-field" for="np-oh-new-item-selection"><span class="np-oh-field-label">Søkeresultater</span>';
        echo '<select id="np-oh-new-item-selection" name="new_item[selection]">';
        echo '<option value="">Velg produkt…</option>';
        foreach ($item_search_results as $result_row) {
            if (!is_array($result_row)) {
                continue;
            }
            $option_value = np_order_hub_encode_order_editor_option_value(
                absint($result_row['product_id'] ?? 0),
                absint($result_row['variation_id'] ?? 0)
            );
            if ($option_value === '0:0') {
                continue;
            }
            $label = np_order_hub_format_order_editor_search_result_label($result_row, $currency);
            echo '<option value="' . esc_attr($option_value) . '"' . selected($new_item_form['selection'], $option_value, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select></label>';
        echo '<p><button class="button button-primary" type="submit" formaction="' . esc_url(admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $record['id'])) . '" formmethod="post" name="np_order_hub_add_line_item" value="1">Legg til produkt</button></p>';
        echo '</div>';
    }
    echo '</form>';
    echo '</div>';

    if (!empty($shipping_lines)) {
        echo '<div class="np-oh-charge-lines">';
        foreach ($shipping_lines as $shipping_line) {
            if (!is_array($shipping_line)) {
                continue;
            }
            $shipping_total_value = np_order_hub_parse_numeric_value($shipping_line['total'] ?? null);
            $shipping_meta_lines = np_order_hub_format_meta_lines($shipping_line['meta_data'] ?? array());
            echo '<div class="np-oh-charge-line">';
            echo '<div>';
            echo '<span class="np-oh-charge-line-title">' . esc_html((string) ($shipping_line['method_title'] ?? 'Frakt')) . '</span>';
            if (!empty($shipping_meta_lines)) {
                foreach ($shipping_meta_lines as $meta_line) {
                    echo '<span class="np-oh-charge-line-meta">' . esc_html($meta_line) . '</span>';
                }
            }
            echo '</div>';
            echo '<strong>' . esc_html(np_order_hub_format_money($shipping_total_value !== null ? $shipping_total_value : 0, $currency)) . '</strong>';
            echo '</div>';
        }
        echo '</div>';
    }

    np_order_hub_render_order_editor_totals_summary($live_order, $currency);

    echo '<details class="np-oh-advanced-edit">';
    echo '<summary>Rediger frakt og gebyrer</summary>';
    echo '<div class="np-oh-items-section">';
    echo '<div class="np-oh-two-col">';
    echo '<div>';
    echo '<h3>Fraktlinjer</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_shipping');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    if (empty($shipping_lines)) {
        echo '<p class="description">Ingen fraktlinjer på denne ordren.</p>';
    } else {
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>Tittel</th><th>Totalt</th><th>Fjern</th></tr></thead><tbody>';
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
            echo '<td><label><input type="checkbox" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][remove]" value="1" /> Fjern</label></td>';
            echo '<input type="hidden" name="shipping_lines[' . esc_attr((string) $shipping_id) . '][method_id]" value="' . esc_attr((string) ($shipping_line['method_id'] ?? '')) . '" />';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '<h4>Legg til fraktlinje</h4>';
    echo '<div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
    echo '<div><label><strong>Tittel</strong><br /><input type="text" name="new_shipping[method_title]" class="regular-text" value="' . esc_attr((string) $new_shipping_form['method_title']) . '" /></label></div>';
    echo '<div><label><strong>Method ID</strong><br /><input type="text" name="new_shipping[method_id]" value="' . esc_attr((string) $new_shipping_form['method_id']) . '" style="width:140px;" /></label></div>';
    echo '<div><label><strong>Totalt</strong><br /><input type="text" name="new_shipping[total]" value="' . esc_attr((string) $new_shipping_form['total']) . '" style="width:110px;" /></label></div>';
    echo '</div>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_shipping" value="1">Lagre frakt</button></p>';
    echo '</form>';
    echo '</div>';

    echo '<div>';
    echo '<h3>Gebyrer / rabatter</h3>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_update_fees');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    if (empty($fee_lines)) {
        echo '<p class="description">Ingen gebyrlinjer på denne ordren.</p>';
    } else {
        echo '<table class="widefat striped">';
        echo '<thead><tr><th>Navn</th><th>Beløp</th><th>Fjern</th></tr></thead><tbody>';
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
            echo '<td><label><input type="checkbox" name="fee_lines[' . esc_attr((string) $fee_id) . '][remove]" value="1" /> Fjern</label></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '<h4>Legg til gebyr / rabatt</h4>';
    echo '<p class="description">Bruk negativt beløp for rabatt.</p>';
    echo '<div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
    echo '<div><label><strong>Navn</strong><br /><input type="text" name="new_fee[name]" class="regular-text" value="' . esc_attr((string) $new_fee_form['name']) . '" /></label></div>';
    echo '<div><label><strong>Beløp</strong><br /><input type="text" name="new_fee[amount]" value="' . esc_attr((string) $new_fee_form['amount']) . '" style="width:110px;" /></label></div>';
    echo '</div>';
    echo '<p><button class="button" type="submit" name="np_order_hub_update_fees" value="1">Lagre gebyrer / rabatter</button></p>';
    echo '</form>';
    echo '</div>';
    echo '</div>';
    echo '<form method="post" style="margin-top:12px;">';
    wp_nonce_field('np_order_hub_recalculate_order');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_recalculate_order" value="1">Beregn på nytt</button>';
    echo '</form>';
    echo '</div>';
    echo '</details>';
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
        echo '<p class="description">Legg inn Help Scout API-token og mailbox-ID i <a href="' . esc_url($settings_url) . '">Help Scout-innstillinger</a>.</p>';
    } elseif ($help_scout_email === '') {
        echo '<p class="description">Kunde-e-post mangler på denne ordren.</p>';
    } else {
        echo '<p><strong>Kunde:</strong> ' . esc_html($help_scout_email) . '</p>';
        echo '<form method="post" style="max-width: 900px;">';
        wp_nonce_field('np_order_hub_help_scout_send');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<table class="form-table">';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-subject">Emne</label></th>';
        echo '<td><input id="np-order-hub-help-scout-subject" name="help_scout_subject" type="text" class="regular-text" value="' . esc_attr($help_scout_subject_value) . '" /></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-status">Status</label></th>';
        echo '<td><select id="np-order-hub-help-scout-status" name="help_scout_status">';
        foreach ($help_scout_status_labels as $key => $label) {
            $selected = selected($help_scout_status_value, $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select></td></tr>';
        echo '<tr><th scope="row"><label for="np-order-hub-help-scout-message">Melding</label></th>';
        echo '<td><textarea id="np-order-hub-help-scout-message" name="help_scout_message" rows="6" class="large-text">' . esc_textarea($help_scout_message_value) . '</textarea></td></tr>';
        echo '</table>';
        echo '<p><button class="button button-primary" type="submit" name="np_order_hub_help_scout_send" value="1">Send melding</button></p>';
        echo '</form>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="postbox">';
    echo '<h2 class="hndle">Reklamasjon</h2>';
    echo '<div class="inside">';
    $token_missing = np_order_hub_get_store_token($store) === '';
    if ($token_missing) {
        echo '<p>Butikktoken mangler i hub-innstillingene.</p>';
    } elseif (empty($line_items)) {
        echo '<p>Ingen varelinjer funnet for denne ordren.</p>';
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
        echo '<th>Velg</th>';
        echo '<th>Produkt</th>';
        echo '<th>Bestilt antall</th>';
        echo '<th>Reklamasjonsantall</th>';
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
        echo '<input type="checkbox" name="reklamasjon_allow_oos" value="1"' . $allow_checked . ' /> Opprett selv om varen er utsolgt (kunden venter på lager)';
        echo '</label>';
        echo '</p>';
        if ($reklamasjon_popup_message !== '') {
            echo '<input type="hidden" id="np-order-hub-reklamasjon-popup" value="' . esc_attr($reklamasjon_popup_message) . '" />';
        }
        echo '<p style="margin-top:12px;">';
        echo '<button class="button button-primary" type="submit" name="np_order_hub_create_reklamasjon" value="1">Opprett reklamasjonsordre</button>';
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
    echo '<h2 class="hndle">Produktmeta</h2>';
    echo '<div class="inside">';
    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th>Produkt</th>';
    echo '<th>Qty</th>';
    echo '<th>Linjesum</th>';
    echo '<th>SKU</th>';
    echo '<th>Detaljer</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    if (empty($line_items)) {
        echo '<tr><td colspan="5">Ingen varelinjer funnet.</td></tr>';
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
