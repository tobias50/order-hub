<?php
if (!defined('ABSPATH')) {
    exit;
}

if (!defined('NP_ORDER_HUB_WPO_ORDER_PREFIX_MAP_OPTION')) {
    define('NP_ORDER_HUB_WPO_ORDER_PREFIX_MAP_OPTION', 'np_order_hub_wpo_order_prefix_map');
}
if (!defined('NP_ORDER_HUB_WPO_ORDER_PREFIX_NEXT_OPTION')) {
    define('NP_ORDER_HUB_WPO_ORDER_PREFIX_NEXT_OPTION', 'np_order_hub_wpo_order_prefix_next');
}
if (!defined('NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_OPTION')) {
    define('NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_OPTION', 'np_order_hub_wpo_order_prefix_schema');
}
if (!defined('NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_VERSION')) {
    define('NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_VERSION', 1);
}

add_filter('woocommerce_order_number', 'np_order_hub_wpo_apply_site_order_prefix', 20, 2);
add_action('init', 'np_order_hub_wpo_maybe_bootstrap_order_prefix_map', 5);
add_action('init', 'np_order_hub_wpo_ensure_current_site_order_prefix', 6);
add_action('wp_initialize_site', 'np_order_hub_wpo_assign_order_prefix_on_initialize_site', 20, 1);
add_action('wpmu_new_blog', 'np_order_hub_wpo_assign_order_prefix_on_new_blog', 20, 6);

function np_order_hub_wpo_get_main_site_id_for_prefix() {
    if (!is_multisite()) {
        return 0;
    }
    if (function_exists('get_main_site_id')) {
        $network_id = function_exists('get_current_network_id') ? (int) get_current_network_id() : 0;
        $main_site_id = (int) get_main_site_id($network_id);
        if ($main_site_id > 0) {
            return $main_site_id;
        }
    }
    return 1;
}

function np_order_hub_wpo_is_order_prefix_enabled_for_blog($blog_id = 0) {
    if (!is_multisite()) {
        return false;
    }
    $blog_id = absint($blog_id ?: get_current_blog_id());
    if ($blog_id < 1) {
        return false;
    }
    return $blog_id !== np_order_hub_wpo_get_main_site_id_for_prefix();
}

function np_order_hub_wpo_normalize_order_prefix_map($map) {
    if (!is_array($map)) {
        return array();
    }
    $normalized = array();
    foreach ($map as $site_id => $prefix) {
        $site_id = absint($site_id);
        $prefix = absint($prefix);
        if ($site_id < 1 || $prefix < 1) {
            continue;
        }
        $normalized[$site_id] = $prefix;
    }
    ksort($normalized, SORT_NUMERIC);
    return $normalized;
}

function np_order_hub_wpo_get_order_prefix_map() {
    $map = get_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_MAP_OPTION, array());
    return np_order_hub_wpo_normalize_order_prefix_map($map);
}

function np_order_hub_wpo_save_order_prefix_map($map) {
    $normalized = np_order_hub_wpo_normalize_order_prefix_map($map);
    update_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_MAP_OPTION, $normalized);
    return $normalized;
}

function np_order_hub_wpo_get_next_order_prefix_seed($map = array()) {
    $map = np_order_hub_wpo_normalize_order_prefix_map($map);
    $next = absint(get_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_NEXT_OPTION, 1));
    if ($next < 1) {
        $next = 1;
    }
    $used_prefixes = array_values($map);
    while (in_array($next, $used_prefixes, true)) {
        $next++;
    }
    return $next;
}

function np_order_hub_wpo_assign_order_prefix_for_blog($blog_id = 0) {
    $blog_id = absint($blog_id ?: get_current_blog_id());
    if (!np_order_hub_wpo_is_order_prefix_enabled_for_blog($blog_id)) {
        return '';
    }

    $map = np_order_hub_wpo_get_order_prefix_map();
    if (isset($map[$blog_id]) && (int) $map[$blog_id] > 0) {
        return (string) (int) $map[$blog_id];
    }

    $next = np_order_hub_wpo_get_next_order_prefix_seed($map);
    $map[$blog_id] = $next;
    $map = np_order_hub_wpo_save_order_prefix_map($map);
    update_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_NEXT_OPTION, $next + 1);

    np_order_hub_wpo_log('order_prefix_assigned', array(
        'blog_id' => $blog_id,
        'prefix' => $next,
    ));

    return (string) $next;
}

function np_order_hub_wpo_get_order_prefix_for_blog($blog_id = 0) {
    $blog_id = absint($blog_id ?: get_current_blog_id());
    if (!np_order_hub_wpo_is_order_prefix_enabled_for_blog($blog_id)) {
        return '';
    }
    $map = np_order_hub_wpo_get_order_prefix_map();
    if (isset($map[$blog_id]) && (int) $map[$blog_id] > 0) {
        return (string) (int) $map[$blog_id];
    }
    return np_order_hub_wpo_assign_order_prefix_for_blog($blog_id);
}

function np_order_hub_wpo_maybe_bootstrap_order_prefix_map() {
    if (!is_multisite()) {
        return;
    }
    $schema = absint(get_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_OPTION, 0));
    if ($schema >= NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_VERSION) {
        return;
    }

    $main_site_id = np_order_hub_wpo_get_main_site_id_for_prefix();
    $map = np_order_hub_wpo_get_order_prefix_map();
    $site_ids = function_exists('get_sites')
        ? get_sites(array(
            'fields' => 'ids',
            'number' => 0,
            'deleted' => 0,
            'archived' => 0,
            'spam' => 0,
        ))
        : array();

    if (is_array($site_ids) && !empty($site_ids)) {
        sort($site_ids, SORT_NUMERIC);
        foreach ($site_ids as $site_id) {
            $site_id = absint($site_id);
            if ($site_id < 1 || $site_id === $main_site_id) {
                continue;
            }
            if (isset($map[$site_id]) && (int) $map[$site_id] > 0) {
                continue;
            }
            $next = np_order_hub_wpo_get_next_order_prefix_seed($map);
            $map[$site_id] = $next;
        }
    }

    $map = np_order_hub_wpo_save_order_prefix_map($map);
    update_site_option(
        NP_ORDER_HUB_WPO_ORDER_PREFIX_NEXT_OPTION,
        np_order_hub_wpo_get_next_order_prefix_seed($map)
    );
    update_site_option(NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_OPTION, NP_ORDER_HUB_WPO_ORDER_PREFIX_SCHEMA_VERSION);
}

function np_order_hub_wpo_ensure_current_site_order_prefix() {
    if (!np_order_hub_wpo_is_order_prefix_enabled_for_blog()) {
        return;
    }
    np_order_hub_wpo_get_order_prefix_for_blog();
}

function np_order_hub_wpo_assign_order_prefix_on_initialize_site($new_site) {
    if (!is_multisite() || !is_object($new_site) || empty($new_site->blog_id)) {
        return;
    }
    np_order_hub_wpo_assign_order_prefix_for_blog((int) $new_site->blog_id);
}

function np_order_hub_wpo_assign_order_prefix_on_new_blog($blog_id, $user_id = 0, $domain = '', $path = '', $site_id = 0, $meta = array()) {
    if (!is_multisite()) {
        return;
    }
    np_order_hub_wpo_assign_order_prefix_for_blog((int) $blog_id);
}

function np_order_hub_wpo_apply_site_order_prefix($order_number, $order) {
    $prefix = np_order_hub_wpo_get_order_prefix_for_blog();
    if ($prefix === '') {
        return $order_number;
    }

    $value = trim((string) $order_number);
    if ($value === '' && $order && is_a($order, 'WC_Order') && method_exists($order, 'get_id')) {
        $value = (string) $order->get_id();
    }
    if ($value === '') {
        return $order_number;
    }

    if (strpos($value, $prefix . '-') === 0) {
        return $value;
    }

    return $prefix . '-' . $value;
}
