<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define base URL for redirect URIs
$base_url = 'http://localhost/ADDWISEcopied';

// Check if constants are already defined before defining them
if (!defined('GOOGLE_CLIENT_ID')) {
    // TODO: Replace with your actual Google Client ID from Google Cloud Console
    // 1. Go to https://console.cloud.google.com/
    // 2. Create a project or select existing one
    // 3. Enable Google+ API
    // 4. Go to Credentials
    // 5. Create OAuth 2.0 Client ID
    // 6. Add authorized redirect URIs:
    //    - http://localhost/ADDWISEcopied/google_callback.php
    //    - http://localhost/ADDWISEcopied/login.php
    define('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com');
}

if (!defined('GOOGLE_CLIENT_SECRET')) {
    // TODO: Replace with your actual Google Client Secret from Google Cloud Console
    define('GOOGLE_CLIENT_SECRET', 'GOCSPX-00000000000000000000000000000000');
}

if (!defined('GOOGLE_REDIRECT_URI')) {
    define('GOOGLE_REDIRECT_URI', $base_url . '/google_callback.php');
}

if (!defined('GOOGLE_AUTH_URL')) {
    define('GOOGLE_AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth');
}

if (!defined('GOOGLE_TOKEN_URL')) {
    define('GOOGLE_TOKEN_URL', 'https://oauth2.googleapis.com/token');
}

if (!defined('GOOGLE_USERINFO_URL')) {
    define('GOOGLE_USERINFO_URL', 'https://www.googleapis.com/oauth2/v3/userinfo');
}

if (!defined('GOOGLE_SCOPES')) {
    define('GOOGLE_SCOPES', 'email profile openid');
}

// Function to validate Google OAuth configuration
function validateGoogleConfig() {
    $errors = [];
    
    if (empty(GOOGLE_CLIENT_ID) || GOOGLE_CLIENT_ID === '1000000000000-0000000000000000000000000000000.apps.googleusercontent.com') {
        $errors[] = "Google Client ID is not configured";
    }
    
    if (empty(GOOGLE_CLIENT_SECRET) || GOOGLE_CLIENT_SECRET === 'GOCSPX-00000000000000000000000000000000') {
        $errors[] = "Google Client Secret is not configured";
    }
    
    if (empty(GOOGLE_REDIRECT_URI)) {
        $errors[] = "Google Redirect URI is not configured";
    }
    
    return $errors;
}

// Function to get Google OAuth URL
function getGoogleAuthUrl($state = '') {
    $params = [
        'client_id' => GOOGLE_CLIENT_ID,
        'redirect_uri' => GOOGLE_REDIRECT_URI,
        'response_type' => 'code',
        'scope' => GOOGLE_SCOPES,
        'access_type' => 'online',
        'prompt' => 'select_account'
    ];
    
    if (!empty($state)) {
        $params['state'] = $state;
    }
    
    return GOOGLE_AUTH_URL . '?' . http_build_query($params);
}

// Function to handle Google OAuth errors
function handleGoogleError($error, $error_description = '') {
    error_log("Google OAuth Error: " . $error . " - " . $error_description);
    
    switch ($error) {
        case 'invalid_request':
            return "Invalid request. Please try again.";
        case 'unauthorized_client':
            return "Unauthorized client. Please contact support.";
        case 'access_denied':
            return "Access was denied. Please try again.";
        case 'invalid_scope':
            return "Invalid scope requested. Please contact support.";
        case 'server_error':
            return "Google server error. Please try again later.";
        default:
            return "Authentication failed. Please try again.";
    }
}

// Validate configuration on include
$config_errors = validateGoogleConfig();
if (!empty($config_errors)) {
    error_log("Google OAuth Configuration Errors: " . implode(", ", $config_errors));
}
?> 