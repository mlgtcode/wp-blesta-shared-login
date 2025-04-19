# Blesta Client Login

Blesta Client Login is a WordPress plugin that allows automatic client authentication to the Blesta billing panel. It provides seamless integration between WordPress and Blesta, enabling users to access the billing panel directly from the WordPress dashboard.

## Features

- Automatic client authentication to the Blesta billing panel.
- Restrict access to specific WordPress user roles.
- Customizable settings for shared login key, redirect URL, and login URL.
- Shortcodes to display a "Billing Panel" button or retrieve the raw URL.
- Supports translations (e.g., Italian, German).

## Installation

1. **Download and Extract**:
   - Download the plugin and extract it to your WordPress plugins directory:  
     `wp-content/plugins/blesta-login/`

2. **Activate the Plugin**:
   - Go to the WordPress admin dashboard.
   - Navigate to **Plugins > Installed Plugins**.
   - Find **Blesta Client Login** and click **Activate**.

3. **Configure Settings**:
   - Go to **Settings > Blesta Login Settings** in the WordPress admin dashboard.
   - Configure the following options:
     - **Shared Login Key**: The key used to generate the HMAC-SHA256 hash for authentication.
     - **Redirect URL**: The URL to redirect users after logging in.
     - **Login URL**: The full URL to the Blesta shared login endpoint.
     - **User Identifier**: Choose between `username` (default) or `email` for authentication.
     - **Restrict to User Group**: Restrict access to specific WordPress user roles.

4. **Use Shortcodes**:
   - Add the following shortcodes to your WordPress pages or posts:
     - `[blesta_login]`: Displays a "Billing Panel" button for logged-in users.
     - `[blesta_login_raw]`: Returns the raw URL for the Billing Panel.

## Shortcodes

### `[blesta_login]`
Displays a button that redirects logged-in users to the Blesta Billing Panel.

### `[blesta_login_raw]`
Returns the raw URL for the Blesta Billing Panel, which can be used in custom implementations.

## Disclaimer

This plugin is provided "as is" without any warranties or guarantees. The author is not responsible for any damages, security breaches, or issues caused by the use of this plugin. Use it at your own risk.

### Security Information

- **Shared Login Key**: Ensure the shared login key is kept confidential and not exposed publicly. It is used to generate secure HMAC-SHA256 hashes for authentication.
- **HTTPS**: Always use HTTPS for the `Login URL` and `Redirect URL` to ensure secure communication between WordPress and Blesta.
- **User Roles**: Restrict access to the plugin settings and functionality to trusted user roles only.
- **Regular Updates**: Keep the plugin and WordPress installation up to date to avoid vulnerabilities.