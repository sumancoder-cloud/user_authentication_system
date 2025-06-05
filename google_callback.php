<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
error_log("=== Google Callback Script Started ===");
error_log("Script path: " . __FILE__);
error_log("Request URI: " . $_SERVER['REQUEST_URI']);
error_log("Document Root: " . $_SERVER['DOCUMENT_ROOT']);
error_log("PHP Version: " . PHP_VERSION);

require_once 'config.php';
require_once 'auth.php';
require_once 'google_config.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Function to handle errors and redirect
function handleError($message, $redirect = 'login.php') {
    error_log("Google Auth Error: " . $message);
    $_SESSION['error'] = $message;
    header("Location: " . $redirect);
    exit();
}

// Function to validate state parameter
function validateState($state) {
    if (!isset($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
        return false;
    }
    return true;
}

// Check for OAuth errors
if (isset($_GET['error'])) {
    $error_message = handleGoogleError($_GET['error'], $_GET['error_description'] ?? '');
    handleError($error_message);
}

// Validate state parameter if present
if (isset($_GET['state']) && !validateState($_GET['state'])) {
    handleError("Invalid state parameter. Possible CSRF attack.");
}

// Clear OAuth state
unset($_SESSION['oauth_state']);

// Check if we have an authorization code
if (!isset($_GET['code'])) {
    handleError("No authorization code received");
}

try {
    // Exchange authorization code for access token
    $token_data = [
        'code' => $_GET['code'],
        'client_id' => GOOGLE_CLIENT_ID,
        'client_secret' => GOOGLE_CLIENT_SECRET,
        'redirect_uri' => GOOGLE_REDIRECT_URI,
        'grant_type' => 'authorization_code'
    ];

    $ch = curl_init(GOOGLE_TOKEN_URL);
    if ($ch === false) {
        throw new Exception("Failed to initialize cURL");
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($token_data),
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if ($response === false) {
        throw new Exception("cURL error: " . curl_error($ch));
    }
    
    curl_close($ch);
    
    if ($http_code !== 200) {
        throw new Exception("HTTP error: " . $http_code);
    }
    
    $token = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response");
    }
    
    if (!isset($token['access_token'])) {
        throw new Exception("No access token in response");
    }

    // Get user info using access token
    $ch = curl_init(GOOGLE_USERINFO_URL);
    if ($ch === false) {
        throw new Exception("Failed to initialize cURL for user info");
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token['access_token']],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2
    ]);
    
    $user_info_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if ($user_info_response === false) {
        throw new Exception("cURL error getting user info: " . curl_error($ch));
    }
    
    curl_close($ch);
    
    if ($http_code !== 200) {
        throw new Exception("HTTP error getting user info: " . $http_code);
    }
    
    $user_info = json_decode($user_info_response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response for user info");
    }
    
    if (!isset($user_info['email']) || !isset($user_info['sub'])) {
        throw new Exception("Missing required user info");
    }

    // Initialize Auth class
    $auth = new Auth($conn);
    
    // Get or create user
    $email = $user_info['email'];
    $name = $user_info['name'] ?? '';
    $google_id = $user_info['sub'];
    
    // Check if user exists
    $user = $auth->getUserByEmail($email);
    
    if (!$user) {
        // For Google users, always use email as username
        $username = $email;
        $password = bin2hex(random_bytes(16)); // Generate secure random password
        
        $result = $auth->register($name, $username, $email, $password, 'user', true);
        
        if (!$result['success']) {
            throw new Exception("Failed to create account: " . $result['message']);
        }
        
        $user = $auth->getUserByEmail($email);
        if (!$user) {
            throw new Exception("Failed to retrieve newly created user");
        }
    }
    
    // Set session variables
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $email; // Always use email as username for Google users
    $_SESSION['role'] = $user['role'];
    $_SESSION['logged_in'] = true;
    $_SESSION['is_google_account'] = true;
    $_SESSION['last_activity'] = time();
    $_SESSION['user_email'] = $email;
    
    // Clear any temporary session data
    unset($_SESSION['google_auth_started']);
    unset($_SESSION['selected_role']);
    
    // Log successful login
    error_log("Successful Google login for user: " . $email);
    
    // Redirect to welcome page
    header("Location: welcome.php");
    exit();

} catch (Exception $e) {
    error_log("Google Auth Exception: " . $e->getMessage());
    handleError("Authentication failed: " . $e->getMessage());
}

// If we get here, something went wrong
handleError("Unexpected error during Google authentication");
?> 