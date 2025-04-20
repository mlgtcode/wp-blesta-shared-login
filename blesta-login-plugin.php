<?php
/*
Plugin Name: Blesta Client Login
Description: Automatic client auth to Blesta billing panel
Version: 1.0
Author: MLGT
Author URI: https://www.mlgt.info
Text Domain: blesta-client-login
Domain Path: /languages
*/

add_action('plugins_loaded', function () {
    load_plugin_textdomain('blesta-client-login', false, 'blesta-login/languages');
});

add_action('admin_menu', function () {
    $user_group = get_option('billing_panel_user_group', '');
    $current_user = wp_get_current_user();

    if (!empty($user_group) && !in_array($user_group, $current_user->roles)) {
        return;
    }

    add_menu_page(
        __('Billing Panel', 'blesta-client-login'),
        __('Billing Panel', 'blesta-client-login'),
        'manage_options',
        'billing-panel',
        'redirect_to_billing_panel',
        'dashicons-admin-links',
        100
    );
});

add_action('admin_menu', function () {
    add_options_page(
        __('Blesta Login Settings', 'blesta-client-login'),
        __('Blesta Login Settings', 'blesta-client-login'),
        'manage_options',
        'blesta-login-settings',
        'billing_panel_settings_page'
    );
});

function encrypt_blesta_secret($key) {
    $encryption_key = wp_salt('auth'); // Use WordPress salt for encryption
    return base64_encode(openssl_encrypt($key, 'aes-256-cbc', $encryption_key, 0, substr($encryption_key, 0, 16)));
}

function decrypt_blesta_secret($encrypted_key) {
    $encryption_key = wp_salt('auth');
    return openssl_decrypt(base64_decode($encrypted_key), 'aes-256-cbc', $encryption_key, 0, substr($encryption_key, 0, 16));
}

function billing_panel_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['billing_panel_settings_nonce']) && wp_verify_nonce($_POST['billing_panel_settings_nonce'], 'billing_panel_settings')) {
        if (!empty($_POST['billing_panel_key'])) {
            $encrypted_key = encrypt_blesta_secret(sanitize_text_field($_POST['billing_panel_key']));
            update_option('billing_panel_key', $encrypted_key, false);
        }
        update_option('billing_panel_redirect_url', esc_url_raw($_POST['billing_panel_redirect_url']));
        update_option('billing_panel_login_url', esc_url_raw($_POST['billing_panel_login_url']));
        update_option('billing_panel_user_identifier', sanitize_text_field($_POST['billing_panel_user_identifier']));
        update_option('billing_panel_user_group', sanitize_text_field($_POST['billing_panel_user_group']));
        echo '<div class="updated"><p>' . __('Settings saved.', 'blesta-client-login') . '</p></div>';
    }

    $key = get_option('billing_panel_key', '');
    if (!empty($key)) {
        $key = decrypt_blesta_secret($key);
    }
    $redirect_url = get_option('billing_panel_redirect_url', site_url());
    $login_url = get_option('billing_panel_login_url', 'https://demo.tld/path_to_blesta/plugin/shared_login/');
    $user_identifier = get_option('billing_panel_user_identifier', 'username');
    $user_group = get_option('billing_panel_user_group', '');

    global $wp_roles;
    $roles = $wp_roles->roles;

    ?>
    <div class="wrap">
        <h1><?php _e('Blesta Login Settings', 'blesta-client-login'); ?></h1>
        <form method="POST">
            <?php wp_nonce_field('billing_panel_settings', 'billing_panel_settings_nonce'); ?>
            <style>
                #billing_panel_key {
                    color: transparent;
                    text-shadow: 0 0 5px rgba(0,0,0,0.5);
                }
                #billing_panel_key:focus {
                    color: inherit;
                    text-shadow: none;
                }
            </style>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="billing_panel_key"><?php _e('Shared Login Key', 'blesta-client-login'); ?></label></th>
                    <td>
                        <input type="text" name="billing_panel_key" id="billing_panel_key" value="<?php echo esc_attr($key); ?>" class="regular-text">
                        <p class="description"><?php _e('The shared key used to generate the HMAC-SHA256 hash for authentication. The key is hidden by default and will be visible only when focused.', 'blesta-client-login'); ?></p>
                        <p class="description"><?php _e('You can find the key in Blesta under <strong>[Settings] > [Company] > [Plugins] > [Shared Login]</strong>.', 'blesta-client-login'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="billing_panel_redirect_url"><?php _e('Redirect URL', 'blesta-client-login'); ?></label></th>
                    <td>
                        <input type="url" name="billing_panel_redirect_url" id="billing_panel_redirect_url" value="<?php echo esc_attr($redirect_url); ?>" class="regular-text">
                        <p class="description"><?php _e('The URI to redirect the client to after logging in. If not set, the user will be redirected to the Blesta client interface.', 'blesta-client-login'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="billing_panel_login_url"><?php _e('Login URL', 'blesta-client-login'); ?></label></th>
                    <td>
                        <input type="url" name="billing_panel_login_url" id="billing_panel_login_url" value="<?php echo esc_attr($login_url); ?>" class="regular-text">
                        <p class="description"><?php _e('The full URL to the Blesta shared login endpoint (e.g., "https://yourdomain.com/path_to_blesta/plugin/shared_login/").', 'blesta-client-login'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="billing_panel_user_identifier"><?php _e('User Identifier', 'blesta-client-login'); ?></label></th>
                    <td>
                        <select name="billing_panel_user_identifier" id="billing_panel_user_identifier" class="regular-text">
                            <option value="email" <?php selected($user_identifier, 'email'); ?>><?php _e('Email', 'blesta-client-login'); ?></option>
                            <option value="username" <?php selected($user_identifier, 'username'); ?>><?php _e('Username', 'blesta-client-login'); ?></option>
                        </select>
                        <p class="description"><?php _e('Select whether to use the WordPress user\'s email or username as the identifier for Blesta login.', 'blesta-client-login'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="billing_panel_user_group"><?php _e('Restrict to User Group', 'blesta-client-login'); ?></label></th>
                    <td>
                        <select name="billing_panel_user_group" id="billing_panel_user_group" class="regular-text">
                            <option value=""><?php _e('No Restriction', 'blesta-client-login'); ?></option>
                            <?php foreach ($roles as $role_key => $role): ?>
                                <option value="<?php echo esc_attr($role_key); ?>" <?php selected($user_group, $role_key); ?>>
                                    <?php echo esc_html($role['name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="description"><?php _e('Select a user role (e.g., "Administrator", "Editor") to restrict access to the plugin. Leave blank for no restriction.', 'blesta-client-login'); ?></p>
                    </td>
                </tr>
            </table>
            <h2><?php _e('How to Use the Shortcodes', 'blesta-client-login'); ?></h2>
            <p><?php _e('To display a "Billing Panel" button on your WordPress site, use the following shortcode:', 'blesta-client-login'); ?></p>
            <pre><code>[blesta_login]</code></pre>
            <p><?php _e('This shortcode will generate a button that redirects logged-in users to the Billing Panel.', 'blesta-client-login'); ?></p>
            <p><?php _e('To get the raw URL for the Billing Panel, use the following shortcode:', 'blesta-client-login'); ?></p>
            <pre><code>[blesta_login_raw]</code></pre>
            <p><?php _e('This shortcode will return the raw URL for the Billing Panel, which can be used in custom implementations.', 'blesta-client-login'); ?></p>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

function redirect_to_billing_panel() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'blesta-client-login'));
    }

    $key = get_option('billing_panel_key', '');
    if (!empty($key)) {
        $key = decrypt_blesta_secret($key);
    }
    $redirect_url = get_option('billing_panel_redirect_url', site_url());
    $login_url = get_option('billing_panel_login_url', 'https://demo.tld/path_to_blesta/plugin/shared_login/');
    $user_identifier = get_option('billing_panel_user_identifier', 'username');
    $user_group = get_option('billing_panel_user_group', '');

    $current_user = wp_get_current_user();

    if (!empty($user_group) && !in_array($user_group, $current_user->roles)) {
        return;
    }

    $t = time();
    $u = ($user_identifier === 'username') ? $current_user->user_login : $current_user->user_email;
    $r = $redirect_url;
    $h = hash_hmac("sha256", $t . $u . $r, $key);

    $url = $login_url . '?' . http_build_query(compact("t", "u", "r", "h"));

    ?>
    <div class="wrap">
        <h1><?php _e('Billing Panel', 'blesta-client-login'); ?></h1>
        <p><?php _e('Click the button below to access the Billing Panel.', 'blesta-client-login'); ?></p>
        <a href="<?php echo esc_url($url); ?>" class="button button-primary"><?php _e('Billing Panel', 'blesta-client-login'); ?></a>
    </div>
    <?php
}

add_shortcode('blesta_login', function () {
    if (is_user_logged_in()) {
        $key = get_option('billing_panel_key', '');
        if (!empty($key)) {
            $key = decrypt_blesta_secret($key);
        }
        $redirect_url = get_option('billing_panel_redirect_url', site_url());
        $login_url = get_option('billing_panel_login_url', 'https://demo.tld/path_to_blesta/plugin/shared_login/');
        $user_identifier = get_option('billing_panel_user_identifier', 'username');
        $user_group = get_option('billing_panel_user_group', '');

        $current_user = wp_get_current_user();

        if (!empty($user_group) && !in_array($user_group, $current_user->roles)) {
            return '';
        }

        $t = time();
        $u = ($user_identifier === 'username') ? $current_user->user_login : $current_user->user_email;
        $r = $redirect_url;
        $h = hash_hmac("sha256", $t . $u . $r, $key);

        $url = $login_url . '?' . http_build_query(compact("t", "u", "r", "h"));
        return '<a href="' . esc_url($url) . '" class="button">' . __('Billing Panel', 'blesta-client-login') . '</a>';
    } else {
        return '<p>' . __('You must be logged in to access the Billing Panel.', 'blesta-client-login') . '</p>';
    }
});

add_shortcode('blesta_login_raw', function () {
    if (is_user_logged_in()) {
        $key = get_option('billing_panel_key', '');
        if (!empty($key)) {
            $key = decrypt_blesta_secret($key);
        }
        $redirect_url = get_option('billing_panel_redirect_url', site_url());
        $login_url = get_option('billing_panel_login_url', 'https://demo.tld/path_to_blesta/plugin/shared_login/');
        $user_identifier = get_option('billing_panel_user_identifier', 'username');
        $user_group = get_option('billing_panel_user_group', '');

        $current_user = wp_get_current_user();

        if (!empty($user_group) && !in_array($user_group, $current_user->roles)) {
            return '';
        }

        $t = time();
        $u = ($user_identifier === 'username') ? $current_user->user_login : $current_user->user_email;
        $r = $redirect_url;
        $h = hash_hmac("sha256", $t . $u . $r, $key);

        $url = $login_url . '?' . http_build_query(compact("t", "u", "r", "h"));
        return esc_url($url);
    } else {
        return '';
    }
});
