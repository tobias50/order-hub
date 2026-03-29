<?php
function np_order_hub_help_scout_cases_page_url($search = '', $status_filter = '', $paged = 1, $notice = null) {
    $args = array(
        'page' => 'np-order-hub-cases',
    );
    if ($search !== '') {
        $args['s'] = $search;
    }
    if ($status_filter !== '') {
        $args['status'] = $status_filter;
    }
    if ((int) $paged > 1) {
        $args['paged'] = (int) $paged;
    }
    if (is_array($notice) && !empty($notice['message'])) {
        $args['np_case_notice_type'] = $notice['type'] === 'success' ? 'success' : 'error';
        $args['np_case_notice_msg'] = (string) $notice['message'];
    }

    return add_query_arg($args, admin_url('admin.php'));
}

function np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, $notice) {
    wp_safe_redirect(np_order_hub_help_scout_cases_page_url($search, $status_filter, $paged, $notice));
    exit;
}

function np_order_hub_help_scout_cases_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    np_order_hub_ensure_help_scout_case_tables();

    $search = sanitize_text_field((string) ($_GET['s'] ?? ''));
    $status_filter = sanitize_key((string) ($_GET['status'] ?? ''));
    $status_options = np_order_hub_help_scout_case_status_options();
    if ($status_filter !== '' && !isset($status_options[$status_filter])) {
        $status_filter = '';
    }
    $paged = max(1, absint($_GET['paged'] ?? 1));

    if (!empty($_POST['np_order_hub_case_bulk_apply'])) {
        check_admin_referer('np_order_hub_case_bulk_action');
        $action = sanitize_key((string) ($_POST['np_order_hub_case_bulk_action'] ?? ''));
        $case_ids = array_values(array_unique(array_filter(array_map('absint', (array) ($_POST['case_ids'] ?? array())))));
        $target_status = '';
        $success_label = '';

        if ($action === 'close_cases') {
            $target_status = 'closed';
            $success_label = 'Lukket';
        } elseif ($action === 'open_cases') {
            $target_status = 'active';
            $success_label = 'Aktiverte';
        }

        if ($target_status === '') {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => 'Velg en gyldig bulkhandling.',
            ));
        }
        if (empty($case_ids)) {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => 'Velg minst én sak.',
            ));
        }

        $updated = 0;
        $first_error = '';
        foreach ($case_ids as $case_id) {
            $result = np_order_hub_help_scout_set_case_status($case_id, $target_status);
            if (is_wp_error($result)) {
                if ($first_error === '') {
                    $first_error = $result->get_error_message();
                }
                continue;
            }
            $updated++;
        }

        if ($updated < 1) {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => $first_error !== '' ? $first_error : 'Ingen saker ble oppdatert.',
            ));
        }

        $message = $success_label . ' ' . $updated . ' ' . ($updated === 1 ? 'sak.' : 'saker.');
        if ($first_error !== '') {
            $message .= ' Noen saker kunne ikke oppdateres.';
        }
        np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
            'type' => 'success',
            'message' => $message,
        ));
    }

    $single_action = sanitize_key((string) ($_GET['np_case_action'] ?? ''));
    $single_case_id = absint($_GET['case_id'] ?? 0);
    if ($single_action !== '' && $single_case_id > 0) {
        $nonce = isset($_GET['_wpnonce']) ? (string) wp_unslash($_GET['_wpnonce']) : '';
        if (!wp_verify_nonce($nonce, 'np_order_hub_case_action_' . $single_case_id . '_' . $single_action)) {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => 'Ugyldig sikkerhetsnøkkel for saksoppdatering.',
            ));
        }

        $target_status = $single_action === 'close' ? 'closed' : ($single_action === 'open' ? 'active' : '');
        if ($target_status === '') {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => 'Ugyldig handling for sak.',
            ));
        }

        $result = np_order_hub_help_scout_set_case_status($single_case_id, $target_status);
        if (is_wp_error($result)) {
            np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
                'type' => 'error',
                'message' => $result->get_error_message(),
            ));
        }

        np_order_hub_help_scout_cases_page_redirect($search, $status_filter, $paged, array(
            'type' => 'success',
            'message' => $target_status === 'closed' ? 'Saken ble lukket.' : 'Saken ble aktivert.',
        ));
    }

    global $wpdb;
    $table = np_order_hub_help_scout_cases_table_name();
    $per_page = 30;
    $offset = ($paged - 1) * $per_page;
    $where = array();
    $args = array();

    if ($search !== '') {
        $like = '%' . $wpdb->esc_like($search) . '%';
        $where[] = '(subject LIKE %s OR customer_name LIKE %s OR customer_email LIKE %s OR preview LIKE %s)';
        array_push($args, $like, $like, $like, $like);
    }
    if ($status_filter === 'active') {
        $where[] = '(remote_status = %s OR remote_status = %s)';
        $args[] = 'active';
        $args[] = 'pending';
    } elseif ($status_filter === 'closed') {
        $where[] = 'remote_status = %s';
        $args[] = 'closed';
    }

    $where_sql = '';
    if (!empty($where)) {
        $where_sql = 'WHERE ' . implode(' AND ', $where);
    }

    $count_sql = "SELECT COUNT(*) FROM $table $where_sql";
    $total_items = !empty($args)
        ? (int) $wpdb->get_var($wpdb->prepare($count_sql, $args))
        : (int) $wpdb->get_var($count_sql);

    $items_sql = "SELECT * FROM $table $where_sql ORDER BY last_thread_at_gmt DESC, id DESC LIMIT %d OFFSET %d";
    $items_args = array_merge($args, array($per_page, $offset));
    $items = $wpdb->get_results($wpdb->prepare($items_sql, $items_args), ARRAY_A);
    if (!is_array($items)) {
        $items = array();
    }

    $notice_message = sanitize_text_field((string) ($_GET['np_case_notice_msg'] ?? ''));
    $notice_type = sanitize_key((string) ($_GET['np_case_notice_type'] ?? ''));

    echo '<div class="wrap">';
    echo '<h1>Saker</h1>';
    if ($notice_message !== '') {
        echo '<div class="' . esc_attr($notice_type === 'success' ? 'updated' : 'error') . '"><p>' . esc_html($notice_message) . '</p></div>';
    }

    echo '<form method="get" style="margin:16px 0;">';
    echo '<input type="hidden" name="page" value="np-order-hub-cases" />';
    echo '<input type="search" name="s" value="' . esc_attr($search) . '" placeholder="Søk kunde, e-post eller emne" style="width:280px;" /> ';
    echo '<select name="status">';
    echo '<option value="">Alle statuser</option>';
    foreach ($status_options as $key => $label) {
        echo '<option value="' . esc_attr($key) . '"' . selected($status_filter, $key, false) . '>' . esc_html($label) . '</option>';
    }
    echo '</select> ';
    echo '<button class="button">Filtrer</button>';
    if ($search !== '' || $status_filter !== '') {
        echo ' <a class="button" href="' . esc_url(admin_url('admin.php?page=np-order-hub-cases')) . '">Nullstill</a>';
    }
    echo '</form>';

    $bulk_action_url = np_order_hub_help_scout_cases_page_url($search, $status_filter, $paged);
    echo '<form method="post" class="np-order-hub-case-bulk" action="' . esc_url($bulk_action_url) . '">';
    wp_nonce_field('np_order_hub_case_bulk_action');
    echo '<div class="tablenav top">';
    echo '<div class="alignleft actions">';
    echo '<label class="screen-reader-text" for="np-order-hub-case-bulk-action">Bulk handlinger</label>';
    echo '<select id="np-order-hub-case-bulk-action" name="np_order_hub_case_bulk_action">';
    echo '<option value="">Bulk handlinger</option>';
    echo '<option value="close_cases">Lukk saker</option>';
    echo '<option value="open_cases">Aktiver saker</option>';
    echo '</select> ';
    echo '<button class="button" type="submit" name="np_order_hub_case_bulk_apply" value="1">Bruk</button>';
    echo '</div>';
    echo '</div>';

    echo '<table class="widefat striped">';
    echo '<thead><tr>';
    echo '<th class="check-column"><input type="checkbox" id="np-order-hub-case-select-all" /></th>';
    echo '<th>Kunde</th>';
    echo '<th>Emne</th>';
    echo '<th>Status</th>';
    echo '<th>Sist oppdatert</th>';
    echo '<th>Ordre</th>';
    echo '<th>Handlinger</th>';
    echo '</tr></thead><tbody>';

    if (empty($items)) {
        echo '<tr><td colspan="7">Ingen saker funnet.</td></tr>';
    } else {
        foreach ($items as $case) {
            $case_id = isset($case['id']) ? (int) $case['id'] : 0;
            $customer_name = trim((string) ($case['customer_name'] ?? ''));
            $customer_email = trim((string) ($case['customer_email'] ?? ''));
            $customer_label = $customer_name !== '' ? $customer_name : ($customer_email !== '' ? $customer_email : 'Ukjent kunde');
            $preview = np_order_hub_help_scout_case_preview($case);
            $subject = trim((string) ($case['subject'] ?? ''));
            $normalized_status = np_order_hub_help_scout_normalize_case_status((string) ($case['remote_status'] ?? ''));
            $status = np_order_hub_help_scout_case_status_label($normalized_status);
            $last_thread = trim((string) ($case['last_thread_at_gmt'] ?? ''));
            $last_thread_label = $last_thread !== '' && $last_thread !== '0000-00-00 00:00:00'
                ? get_date_from_gmt($last_thread, 'd.m.Y H:i')
                : '—';
            $links = np_order_hub_help_scout_get_case_links($case_id);
            $orders_html = '—';
            if (!empty($links)) {
                $parts = array();
                foreach ($links as $record) {
                    $order_label = !empty($record['order_number']) ? '#' . $record['order_number'] : '#' . (int) ($record['order_id'] ?? 0);
                    $url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $record['id']);
                    $parts[] = '<a href="' . esc_url($url) . '">' . esc_html($order_label . ' ' . ($record['store_name'] ?? '')) . '</a>';
                }
                $orders_html = implode('<br />', $parts);
            }
            $details_url = admin_url('admin.php?page=np-order-hub-case-details&case_id=' . $case_id);
            $remote_url = trim((string) ($case['remote_web_url'] ?? ''));
            $row_action = $normalized_status === 'closed' ? 'open' : 'close';
            $row_action_label = $normalized_status === 'closed' ? 'Aktiver' : 'Lukk';
            $action_url = wp_nonce_url(
                add_query_arg(
                    array(
                        'np_case_action' => $row_action,
                        'case_id' => $case_id,
                    ),
                    np_order_hub_help_scout_cases_page_url($search, $status_filter, $paged)
                ),
                'np_order_hub_case_action_' . $case_id . '_' . $row_action
            );

            echo '<tr>';
            echo '<td class="check-column"><input type="checkbox" name="case_ids[]" value="' . esc_attr((string) $case_id) . '" /></td>';
            echo '<td><strong>' . esc_html($customer_label) . '</strong>';
            if ($customer_email !== '' && $customer_email !== $customer_label) {
                echo '<br /><span class="description">' . esc_html($customer_email) . '</span>';
            }
            echo '</td>';
            echo '<td><strong>' . esc_html($subject !== '' ? $subject : '(uten emne)') . '</strong>';
            if ($preview !== '') {
                echo '<br /><span class="description">' . esc_html($preview) . '</span>';
            }
            echo '</td>';
            echo '<td>' . esc_html($status) . '</td>';
            echo '<td>' . esc_html($last_thread_label) . '</td>';
            echo '<td>' . wp_kses_post($orders_html) . '</td>';
            echo '<td><a class="button button-small" href="' . esc_url($details_url) . '">Åpne sak</a> ';
            echo '<a class="button button-small" href="' . esc_url($action_url) . '">' . esc_html($row_action_label) . '</a> ';
            if ($remote_url !== '') {
                echo '<a class="button button-small" href="' . esc_url($remote_url) . '" target="_blank" rel="noopener">Help Scout</a>';
            }
            echo '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody></table>';
    echo '</form>';

    $total_pages = $per_page > 0 ? (int) ceil($total_items / $per_page) : 1;
    if ($total_pages > 1) {
        echo '<div class="tablenav"><div class="tablenav-pages" style="margin:16px 0;">';
        echo paginate_links(array(
            'base' => add_query_arg('paged', '%#%', np_order_hub_help_scout_cases_page_url($search, $status_filter, 1)),
            'format' => '',
            'current' => $paged,
            'total' => $total_pages,
        ));
        echo '</div></div>';
    }

    echo '<script>
        document.addEventListener("DOMContentLoaded", function() {
            var selectAll = document.getElementById("np-order-hub-case-select-all");
            if (selectAll) {
                selectAll.addEventListener("change", function() {
                    var boxes = document.querySelectorAll(".np-order-hub-case-bulk input[name=\'case_ids[]\']");
                    boxes.forEach(function(box) {
                        box.checked = selectAll.checked;
                    });
                });
            }
        });
    </script>';

    echo '</div>';
}

function np_order_hub_help_scout_case_details_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    np_order_hub_ensure_help_scout_case_tables();
    $case_id = absint($_GET['case_id'] ?? 0);
    $case = np_order_hub_help_scout_get_case($case_id);

    echo '<div class="wrap">';
    echo '<h1>Saksdetaljer</h1>';
    echo '<p><a href="' . esc_url(admin_url('admin.php?page=np-order-hub-cases')) . '">&larr; Tilbake til saker</a></p>';

    if (!$case) {
        echo '<div class="error"><p>Saken ble ikke funnet.</p></div></div>';
        return;
    }

    $notice = null;
    if (!empty($_POST['np_order_hub_help_scout_case_toggle_status'])) {
        check_admin_referer('np_order_hub_help_scout_case_toggle_status');
        $target_status = np_order_hub_help_scout_normalize_case_status((string) ($_POST['case_status_target'] ?? 'active'));
        $updated_case = np_order_hub_help_scout_set_case_status($case, $target_status);
        if (is_wp_error($updated_case)) {
            $notice = array('type' => 'error', 'message' => $updated_case->get_error_message());
        } else {
            $case = $updated_case;
            $notice = array(
                'type' => 'updated',
                'message' => $target_status === 'closed' ? 'Saken ble lukket.' : 'Saken ble aktivert.',
            );
        }
    }

    if (!empty($_POST['np_order_hub_help_scout_case_reply'])) {
        check_admin_referer('np_order_hub_help_scout_case_reply');
        $settings = np_order_hub_get_help_scout_settings();
        $message = trim((string) wp_unslash($_POST['case_reply_message'] ?? ''));
        $status = np_order_hub_help_scout_normalize_case_status((string) ($_POST['case_reply_status'] ?? 'active'));
        if ($message === '') {
            $notice = array('type' => 'error', 'message' => 'Melding kan ikke være tom.');
        } else {
            $customer = array();
            if (!empty($case['customer_email'])) {
                $customer['email'] = (string) $case['customer_email'];
            }
            $sent = np_order_hub_help_scout_send_reply($settings, (int) $case['conversation_id'], $message, $status, $customer);
            if (is_wp_error($sent)) {
                $notice = array('type' => 'error', 'message' => $sent->get_error_message());
            } else {
                $status_error = null;
                if (in_array($status, array('active', 'closed'), true)) {
                    $status_result = np_order_hub_help_scout_update_conversation_status($settings, (int) $case['conversation_id'], $status);
                    if (is_wp_error($status_result)) {
                        $status_error = $status_result->get_error_message();
                    } else {
                        np_order_hub_help_scout_mark_case_closed_in_remote((int) $case['conversation_id'], $status === 'closed');
                    }
                }
                $links = np_order_hub_help_scout_get_case_links((int) $case['id']);
                $synced = np_order_hub_help_scout_sync_conversation_to_local($settings, (int) $case['conversation_id'], $links, false);
                if (is_wp_error($synced)) {
                    $notice = array('type' => 'error', 'message' => $synced->get_error_message());
                } else {
                    $case = $synced;
                    $notice_message = 'Svar sendt.';
                    if ($status_error !== null) {
                        $notice_message .= ' Status i Help Scout ble ikke oppdatert: ' . $status_error;
                    }
                    $notice = array('type' => 'updated', 'message' => $notice_message);
                }
            }
        }
    }

    if (!empty($_POST['np_order_hub_help_scout_case_sync'])) {
        check_admin_referer('np_order_hub_help_scout_case_sync');
        $settings = np_order_hub_get_help_scout_settings();
        $links = np_order_hub_help_scout_get_case_links((int) $case['id']);
        $synced = np_order_hub_help_scout_sync_conversation_to_local($settings, (int) $case['conversation_id'], $links, false);
        if (is_wp_error($synced)) {
            $notice = array('type' => 'error', 'message' => $synced->get_error_message());
        } else {
            $case = $synced;
            $notice = array('type' => 'updated', 'message' => 'Saken ble synkronisert.');
        }
    }

    if (is_array($notice) && !empty($notice['message'])) {
        echo '<div class="' . esc_attr($notice['type'] === 'updated' ? 'updated' : 'error') . '"><p>' . esc_html((string) $notice['message']) . '</p></div>';
    }

    $links = np_order_hub_help_scout_get_case_links((int) $case['id']);
    $messages = np_order_hub_help_scout_get_case_messages((int) $case['id']);
    $remote_url = trim((string) ($case['remote_web_url'] ?? ''));
    $status = np_order_hub_help_scout_normalize_case_status((string) ($case['remote_status'] ?? ''));
    $toggle_target = $status === 'closed' ? 'active' : 'closed';
    $toggle_label = $status === 'closed' ? 'Aktiver sak' : 'Lukk sak';

    echo '<div class="card" style="max-width: 1100px; padding:16px; margin-bottom:16px;">';
    echo '<h2 style="margin-top:0;">' . esc_html((string) ($case['subject'] ?: '(uten emne)')) . '</h2>';
    echo '<p><strong>Kunde:</strong> ' . esc_html((string) (($case['customer_name'] ?: $case['customer_email']) ?: 'Ukjent')) . '</p>';
    if (!empty($case['customer_email'])) {
        echo '<p><strong>E-post:</strong> ' . esc_html((string) $case['customer_email']) . '</p>';
    }
    echo '<p><strong>Status:</strong> ' . esc_html(np_order_hub_help_scout_case_status_label($status)) . '</p>';
    echo '<div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center;">';
    if ($remote_url !== '') {
        echo '<a class="button" href="' . esc_url($remote_url) . '" target="_blank" rel="noopener">Åpne i Help Scout</a>';
    }
    echo '<form method="post" style="margin:0;">';
    wp_nonce_field('np_order_hub_help_scout_case_sync');
    echo '<button class="button" type="submit" name="np_order_hub_help_scout_case_sync" value="1">Synkroniser nå</button>';
    echo '</form>';
    echo '<form method="post" style="margin:0;">';
    wp_nonce_field('np_order_hub_help_scout_case_toggle_status');
    echo '<input type="hidden" name="case_status_target" value="' . esc_attr($toggle_target) . '" />';
    echo '<button class="button" type="submit" name="np_order_hub_help_scout_case_toggle_status" value="1">' . esc_html($toggle_label) . '</button>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo '<div class="card" style="max-width: 1100px; padding:16px; margin-bottom:16px;">';
    echo '<h2 style="margin-top:0;">Koblede ordre</h2>';
    if (empty($links)) {
        echo '<p>Ingen ordre koblet til denne saken.</p>';
    } else {
        echo '<ul style="margin-left:18px;">';
        foreach ($links as $record) {
            $order_label = !empty($record['order_number']) ? '#' . $record['order_number'] : '#' . (int) ($record['order_id'] ?? 0);
            $details_url = admin_url('admin.php?page=np-order-hub-details&record_id=' . (int) $record['id']);
            echo '<li><a href="' . esc_url($details_url) . '">' . esc_html($record['store_name'] . ' ' . $order_label) . '</a></li>';
        }
        echo '</ul>';
    }
    echo '</div>';

    echo '<div class="card" style="max-width: 1100px; padding:16px; margin-bottom:16px;">';
    echo '<h2 style="margin-top:0;">Svar fra Order Hub</h2>';
    echo '<form method="post">';
    wp_nonce_field('np_order_hub_help_scout_case_reply');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="np-order-hub-case-reply-status">Status etter svar</label></th><td><select id="np-order-hub-case-reply-status" name="case_reply_status">';
    foreach (np_order_hub_help_scout_case_status_options() as $key => $label) {
        echo '<option value="' . esc_attr($key) . '"' . selected($status, $key, false) . '>' . esc_html($label) . '</option>';
    }
    echo '</select></td></tr>';
    echo '<tr><th scope="row"><label for="np-order-hub-case-reply-message">Melding</label></th><td><textarea id="np-order-hub-case-reply-message" name="case_reply_message" rows="8" class="large-text"></textarea></td></tr>';
    echo '</table>';
    echo '<p><button class="button button-primary" type="submit" name="np_order_hub_help_scout_case_reply" value="1">Send svar</button></p>';
    echo '</form>';
    echo '</div>';

    echo '<div class="card" style="max-width: 1100px; padding:16px;">';
    echo '<h2 style="margin-top:0;">Tråd</h2>';
    if (empty($messages)) {
        echo '<p>Ingen meldinger lagret ennå.</p>';
    } else {
        foreach ($messages as $message) {
            $author = trim((string) ($message['author_name'] ?: $message['author_email']));
            $author = $author !== '' ? $author : 'Ukjent';
            $thread_type = np_order_hub_help_scout_case_thread_type_label((string) ($message['thread_type'] ?? ''));
            $created = trim((string) ($message['created_at_gmt'] ?? ''));
            $created_label = $created !== '' && $created !== '0000-00-00 00:00:00'
                ? get_date_from_gmt($created, 'd.m.Y H:i')
                : 'Ukjent tidspunkt';

            echo '<div style="border:1px solid #dcdcde; border-radius:8px; padding:14px; margin-bottom:12px;">';
            echo '<p style="margin:0 0 8px;"><strong>' . esc_html($thread_type) . '</strong> | ' . esc_html($author) . ' | ' . esc_html($created_label) . '</p>';
            echo '<div style="line-height:1.5;">' . np_order_hub_help_scout_case_message_html($message) . '</div>';
            echo '</div>';
        }
    }
    echo '</div>';

    echo '</div>';
}
