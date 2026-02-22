<?php
function np_order_hub_help_scout_parse_oauth_error($response, $default_message) {
    $message = $default_message;
    $body = wp_remote_retrieve_body($response);
    $decoded = null;
    if ($body !== '') {
        $decoded = json_decode($body, true);
    }
    if (is_array($decoded)) {
        if (!empty($decoded['error_description'])) {
            $message = (string) $decoded['error_description'];
        } elseif (!empty($decoded['message'])) {
            $message = (string) $decoded['message'];
        } elseif (!empty($decoded['error'])) {
            $message = (string) $decoded['error'];
        }
    } elseif ($body !== '') {
        $message = wp_strip_all_tags((string) $body);
    }
    return $message;
}

function np_order_hub_help_scout_exchange_code($settings, $code) {
    if (empty($settings['client_id']) || empty($settings['client_secret'])) {
        return new WP_Error('missing_help_scout_client', 'Help Scout App ID or Secret missing.');
    }
    $code = trim((string) $code);
    if ($code === '') {
        return new WP_Error('missing_help_scout_code', 'Help Scout OAuth code missing.');
    }

    $response = wp_remote_post('https://api.helpscout.net/v2/oauth2/token', array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret'],
            'redirect_uri' => np_order_hub_help_scout_get_redirect_url(),
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code_status = wp_remote_retrieve_response_code($response);
    if ($code_status < 200 || $code_status >= 300) {
        $message = np_order_hub_help_scout_parse_oauth_error($response, 'Help Scout OAuth exchange failed.');
        return new WP_Error('help_scout_oauth_failed', $message, array(
            'status' => $code_status,
            'body' => wp_remote_retrieve_body($response),
        ));
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['access_token'])) {
        return new WP_Error('help_scout_oauth_failed', 'Help Scout OAuth response missing access token.');
    }

    np_order_hub_help_scout_store_tokens($decoded);

    return $decoded;
}

function np_order_hub_help_scout_refresh_token($settings) {
    if (empty($settings['client_id']) || empty($settings['client_secret'])) {
        return new WP_Error('missing_help_scout_client', 'Help Scout App ID or Secret missing.');
    }
    if (empty($settings['refresh_token'])) {
        return new WP_Error('missing_help_scout_refresh', 'Help Scout refresh token missing.');
    }

    $response = wp_remote_post('https://api.helpscout.net/v2/oauth2/token', array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'grant_type' => 'refresh_token',
            'refresh_token' => $settings['refresh_token'],
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret'],
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code_status = wp_remote_retrieve_response_code($response);
    if ($code_status < 200 || $code_status >= 300) {
        $message = np_order_hub_help_scout_parse_oauth_error($response, 'Help Scout OAuth refresh failed.');
        return new WP_Error('help_scout_oauth_failed', $message, array(
            'status' => $code_status,
            'body' => wp_remote_retrieve_body($response),
        ));
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['access_token'])) {
        return new WP_Error('help_scout_oauth_failed', 'Help Scout refresh response missing access token.');
    }

    np_order_hub_help_scout_store_tokens($decoded, $settings['refresh_token']);

    return $decoded;
}

function np_order_hub_help_scout_can_use_client_credentials($settings) {
    return !empty($settings['client_id']) && !empty($settings['client_secret']);
}

function np_order_hub_help_scout_client_credentials_token($settings) {
    if (!np_order_hub_help_scout_can_use_client_credentials($settings)) {
        return new WP_Error('missing_help_scout_client', 'Help Scout App ID or Secret missing.');
    }

    $response = wp_remote_post('https://api.helpscout.net/v2/oauth2/token', array(
        'timeout' => 20,
        'headers' => array(
            'Accept' => 'application/json',
        ),
        'body' => array(
            'grant_type' => 'client_credentials',
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret'],
        ),
    ));

    if (is_wp_error($response)) {
        return $response;
    }

    $code_status = wp_remote_retrieve_response_code($response);
    if ($code_status < 200 || $code_status >= 300) {
        $message = np_order_hub_help_scout_parse_oauth_error($response, 'Help Scout OAuth client credentials failed.');
        return new WP_Error('help_scout_oauth_failed', $message, array(
            'status' => $code_status,
            'body' => wp_remote_retrieve_body($response),
        ));
    }

    $body = wp_remote_retrieve_body($response);
    $decoded = $body !== '' ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['access_token'])) {
        return new WP_Error('help_scout_oauth_failed', 'Help Scout client credentials response missing access token.');
    }

    np_order_hub_help_scout_store_tokens($decoded, isset($settings['refresh_token']) ? (string) $settings['refresh_token'] : '');

    return $decoded;
}

function np_order_hub_help_scout_get_access_token($settings) {
    $token = isset($settings['token']) ? (string) $settings['token'] : '';
    $expires_at = isset($settings['expires_at']) ? (int) $settings['expires_at'] : 0;
    if ($token !== '' && ($expires_at === 0 || time() < $expires_at)) {
        if ($expires_at === 0 && empty($settings['refresh_token']) && np_order_hub_help_scout_can_use_client_credentials($settings)) {
            $client_credentials = np_order_hub_help_scout_client_credentials_token($settings);
            if (!is_wp_error($client_credentials) && !empty($client_credentials['access_token'])) {
                return (string) $client_credentials['access_token'];
            }
        }
        return $token;
    }

    if (!empty($settings['refresh_token'])) {
        $refreshed = np_order_hub_help_scout_refresh_token($settings);
        if (!is_wp_error($refreshed) && !empty($refreshed['access_token'])) {
            return (string) $refreshed['access_token'];
        }
        if (is_wp_error($refreshed)) {
            return $refreshed;
        }
    }

    if (np_order_hub_help_scout_can_use_client_credentials($settings)) {
        $client_credentials = np_order_hub_help_scout_client_credentials_token($settings);
        if (!is_wp_error($client_credentials) && !empty($client_credentials['access_token'])) {
            return (string) $client_credentials['access_token'];
        }
        if (is_wp_error($client_credentials) && $token === '') {
            return $client_credentials;
        }
    }

    if ($token !== '') {
        return $token;
    }

    return new WP_Error('missing_help_scout_token', 'Help Scout API token missing.');
}

function np_order_hub_help_scout_clean_payload($value) {
    if (is_array($value)) {
        $clean = array();
        foreach ($value as $key => $item) {
            $clean[$key] = np_order_hub_help_scout_clean_payload($item);
        }
        return $clean;
    }
    if (is_string($value)) {
        return wp_check_invalid_utf8($value);
    }
    return $value;
}

function np_order_hub_help_scout_request($settings, $method, $path, $payload = null) {
    $token = np_order_hub_help_scout_get_access_token($settings);
    if (is_wp_error($token)) {
        return $token;
    }

    $path = ltrim((string) $path, '/');
    if ($path === '') {
        return new WP_Error('missing_help_scout_endpoint', 'Help Scout endpoint missing.');
    }

    $url = 'https://api.helpscout.net/v2/' . $path;
    $args = array(
        'timeout' => 20,
        'headers' => array(
            'Authorization' => 'Bearer ' . $token,
            'Accept' => 'application/json',
        ),
        'method' => strtoupper((string) $method),
    );

    if ($payload !== null) {
        $args['headers']['Content-Type'] = 'application/json';
        $clean_payload = np_order_hub_help_scout_clean_payload($payload);
        $body = wp_json_encode($clean_payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            $message = 'Help Scout payload JSON encode failed.';
            if (function_exists('json_last_error_msg')) {
                $message .= ' ' . json_last_error_msg();
            }
            return new WP_Error('help_scout_json_error', $message);
        }
        $args['body'] = $body;
        $args['data_format'] = 'body';
    }

    $response = wp_remote_request($url, $args);
    if (is_wp_error($response)) {
        return $response;
    }

    $code = wp_remote_retrieve_response_code($response);
    if ($code === 401) {
        if (!empty($settings['refresh_token'])) {
            $refreshed = np_order_hub_help_scout_refresh_token($settings);
            if (!is_wp_error($refreshed) && !empty($refreshed['access_token'])) {
                $args['headers']['Authorization'] = 'Bearer ' . (string) $refreshed['access_token'];
                $response = wp_remote_request($url, $args);
                if (is_wp_error($response)) {
                    return $response;
                }
                $code = wp_remote_retrieve_response_code($response);
            }
        }

        if ($code === 401 && np_order_hub_help_scout_can_use_client_credentials($settings)) {
            $client_credentials = np_order_hub_help_scout_client_credentials_token($settings);
            if (!is_wp_error($client_credentials) && !empty($client_credentials['access_token'])) {
                $args['headers']['Authorization'] = 'Bearer ' . (string) $client_credentials['access_token'];
                $response = wp_remote_request($url, $args);
                if (is_wp_error($response)) {
                    return $response;
                }
                $code = wp_remote_retrieve_response_code($response);
            }
        }
    }
    if ($code < 200 || $code >= 300) {
        $body = wp_remote_retrieve_body($response);
        $request_headers = $args['headers'];
        if (isset($request_headers['Authorization'])) {
            $request_headers['Authorization'] = 'Bearer [redacted]';
        }
        $message = 'Help Scout API returned an error.';
        $decoded = null;
        if ($body !== '') {
            $decoded = json_decode($body, true);
        }
        if (is_array($decoded)) {
            if (!empty($decoded['message'])) {
                $message = (string) $decoded['message'];
            } elseif (!empty($decoded['error'])) {
                $message = (string) $decoded['error'];
            } elseif (!empty($decoded['errors']) && is_array($decoded['errors'])) {
                $parts = array();
                foreach ($decoded['errors'] as $error) {
                    if (is_array($error)) {
                        $field = isset($error['field']) ? (string) $error['field'] : '';
                        $error_message = isset($error['message']) ? (string) $error['message'] : '';
                        $parts[] = $field !== '' ? ($field . ': ' . $error_message) : $error_message;
                    } elseif (is_string($error)) {
                        $parts[] = $error;
                    }
                }
                $parts = array_filter($parts, function ($value) {
                    return $value !== '';
                });
                if (!empty($parts)) {
                    $message = implode(' ', $parts);
                }
            }
        } elseif ($body !== '') {
            $message = wp_strip_all_tags((string) $body);
        }
        $message = 'Help Scout API error (' . $code . '): ' . $message;
        return new WP_Error('help_scout_api_error', $message, array(
            'status' => $code,
            'body' => $body,
            'response_body' => $body,
            'decoded' => $decoded,
            'request_body' => isset($args['body']) ? $args['body'] : '',
            'request_headers' => $request_headers,
            'response_headers' => wp_remote_retrieve_headers($response),
            'request_url' => $url,
        ));
    }

    return $response;
}