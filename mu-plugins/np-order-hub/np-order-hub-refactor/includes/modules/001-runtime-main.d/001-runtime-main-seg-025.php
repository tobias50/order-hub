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

        if ($token !== '') {
            update_option(NP_ORDER_HUB_HELP_SCOUT_TOKEN_OPTION, $token);
        }
        update_option(NP_ORDER_HUB_HELP_SCOUT_MAILBOX_OPTION, $mailbox_id);
        update_option(NP_ORDER_HUB_HELP_SCOUT_DEFAULT_STATUS_OPTION, $status);
        update_option(NP_ORDER_HUB_HELP_SCOUT_USER_OPTION, $user_id);
        update_option(NP_ORDER_HUB_HELP_SCOUT_AUTO_LOOKUP_OPTION, $auto_lookup);
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
    echo '<td><label><input id="np-order-hub-help-scout-auto-lookup" name="np_order_hub_help_scout_auto_lookup" type="checkbox" value="1"' . checked(!empty($settings['auto_lookup']), true, false) . ' /> Match innkommende Help Scout-samtaler mot ordre og legg inn intern note</label></td></tr>';
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

    $payload = array();
    if ($record && !empty($record['payload'])) {
        $decoded = json_decode($record['payload'], true);
        if (is_array($decoded)) {
            $payload = $decoded;
        }
    }
    $line_items = isset($payload['line_items']) && is_array($payload['line_items']) ? $payload['line_items'] : array();
    $help_scout_billing = isset($payload['billing']) && is_array($payload['billing']) ? $payload['billing'] : array();
    $help_scout_email = !empty($help_scout_billing['email']) ? sanitize_email((string) $help_scout_billing['email']) : '';
    $help_scout_first_name = !empty($help_scout_billing['first_name']) ? sanitize_text_field((string) $help_scout_billing['first_name']) : '';
    $help_scout_last_name = !empty($help_scout_billing['last_name']) ? sanitize_text_field((string) $help_scout_billing['last_name']) : '';

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

    $status_notice = null;
    if ($record && !empty($_POST['np_order_hub_update_status'])) {
        check_admin_referer('np_order_hub_update_status');
        $new_status = sanitize_key((string) $_POST['order_status']);
        $allowed_statuses = np_order_hub_get_allowed_statuses();
        if (!isset($allowed_statuses[$new_status])) {
            $status_notice = array('type' => 'error', 'message' => 'Invalid status selected.');
        } else {
            $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
            $result = np_order_hub_update_remote_order_status($store, (int) $record['order_id'], $new_status);
            if (is_wp_error($result)) {
                $status_notice = array('type' => 'error', 'message' => $result->get_error_message());
            } else {
                $record = np_order_hub_apply_local_status($record, $new_status);
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

    echo '<div class="wrap">';
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

    echo '<div class="card" style="max-width: 900px; padding: 16px;">';
    echo '<h2 style="margin-top:0;">Order ' . esc_html($order_label) . '</h2>';
    echo '<p><strong>Store:</strong> ' . esc_html($record['store_name']) . '</p>';
    if ($date_label !== '') {
        echo '<p><strong>Date:</strong> ' . esc_html($date_label) . '</p>';
    }
    if ($status_label !== '') {
        echo '<p><strong>Status:</strong> ' . esc_html($status_label) . '</p>';
    }
    $store = np_order_hub_get_store_by_key(isset($record['store_key']) ? $record['store_key'] : '');
    $allowed_statuses = np_order_hub_get_allowed_statuses();
    if (!empty($allowed_statuses)) {
        $token_missing = np_order_hub_get_store_token($store) === '';
        echo '<form method="post" style="margin:12px 0;">';
        wp_nonce_field('np_order_hub_update_status');
        echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
        echo '<label for="np-order-hub-status-update" style="margin-right:6px;"><strong>Update status:</strong></label>';
        echo '<select name="order_status" id="np-order-hub-status-update">';
        foreach ($allowed_statuses as $key => $label) {
            $selected = selected($record['status'], $key, false);
            echo '<option value="' . esc_attr($key) . '"' . $selected . '>' . esc_html($label) . '</option>';
        }
        echo '</select> ';
        echo '<button class="button" type="submit" name="np_order_hub_update_status" value="1">Update</button>';
        if ($token_missing) {
            echo '<p class="description" style="margin:6px 0 0;">Store token missing in hub store settings.</p>';
        }
        echo '</form>';
    }
    $delivery_bucket = np_order_hub_record_delivery_bucket($record);
    echo '<form method="post" style="margin:12px 0;">';
    wp_nonce_field('np_order_hub_update_delivery_bucket');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<label for="np-order-hub-delivery-bucket" style="margin-right:6px;"><strong>Delivery bucket:</strong></label>';
    echo '<select name="delivery_bucket" id="np-order-hub-delivery-bucket">';
    echo '<option value="standard"' . selected($delivery_bucket, 'standard', false) . '>Levering 3-5 dager</option>';
    echo '<option value="scheduled"' . selected($delivery_bucket, 'scheduled', false) . '>Levering til bestemt dato</option>';
    echo '</select> ';
    echo '<button class="button" type="submit" name="np_order_hub_update_delivery_bucket" value="1">Update</button>';
    echo '</form>';
    echo '<p><strong>Total:</strong> ' . esc_html($total_display) . '</p>';
    $packing_url = np_order_hub_build_packing_slip_url(
        $store,
        (int) $record['order_id'],
        (string) $record['order_number'],
        isset($record['payload']) ? $record['payload'] : null
    );
    if (!empty($record['order_admin_url']) || $packing_url !== '') {
        echo '<p>';
        if ($packing_url !== '') {
            echo '<a class="button" href="' . esc_url($packing_url) . '" target="_blank" rel="noopener">Packing slip</a> ';
        }
        if (!empty($record['order_admin_url'])) {
            echo '<a class="button button-primary" href="' . esc_url($record['order_admin_url']) . '" target="_blank" rel="noopener">Open order in store</a>';
        }
        echo '</p>';
    }
    echo '<form method="post" style="margin-top:10px;">';
    wp_nonce_field('np_order_hub_delete_record');
    echo '<input type="hidden" name="record_id" value="' . esc_attr((string) $record['id']) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_delete_record" value="1" onclick="return confirm(\'Remove this order from the hub?\');">Delete from hub</button>';
    echo '</form>';
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

    echo '<h2>Help Scout</h2>';
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

    echo '<h2>Reklamasjon</h2>';
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

    echo '<h2>Items</h2>';
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
}