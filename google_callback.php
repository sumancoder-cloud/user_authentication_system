<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
error_log("=== Google Callback Script Started ===");
error_log("Script path: " . __FILE__);
error_log("Request URI: " . $_SERVER['REQUEST_URI']);
error_log("Document Root: " . $_SERVER['DOCUMENT_ROOT']);
error_log("PHP Version: " . PHP_VERSION);

require_once 'config.php';
require_once 'google_auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Prevent direct access to this file without proper flow
if (!isset($_SESSION['google_auth_started']) || !isset($_SESSION['selected_role'])) {
    error_log("Direct access or invalid session state detected");
    header("Location: signup.php");
    exit();
}

// Clear the google_auth_started flag to prevent back button usage
unset($_SESSION['google_auth_started']);

if (isset($_GET['code'])) {
    error_log("=== Google OAuth Callback Started ===");
    error_log("Authorization code received: " . $_GET['code']);
    
    $google_auth = new GoogleAuth();
    
    try {
        // Get access token
        error_log("Attempting to get access token...");
        $token_data = $google_auth->getAccessToken($_GET['code']);
        error_log("Token data received: " . print_r($token_data, true));
        
        if (isset($token_data['access_token'])) {
            // Get user info
            error_log("Attempting to get user info...");
            $user_info = $google_auth->getUserInfo($token_data['access_token']);
            error_log("User info received: " . print_r($user_info, true));
            
            if (isset($user_info['email'])) {
                // Handle signup/login
                error_log("Attempting to handle Google signup...");
                $result = $google_auth->handleGoogleSignup($user_info, $_SESSION['selected_role']);
                error_log("Signup result: " . print_r($result, true));
                
                if ($result['success']) {
                    // Registration successful, redirect to login
                    error_log("Registration successful, redirecting to login...");
                    $_SESSION['success'] = $result['message'];
                    // Clear any existing auth data
                    unset($_SESSION['temp_auth']);
                    header("Location: login.php");
                    exit();
                } else {
                    if (isset($result['email_exists']) && $result['email_exists']) {
                        // Email already exists, redirect to login
                        error_log("Email already exists, redirecting to login...");
                        $_SESSION['error'] = $result['message'];
                        $_SESSION['email'] = $result['email']; // Pre-fill email in login form
                        // Clear any existing auth data
                        unset($_SESSION['temp_auth']);
                        header("Location: login.php");
                        exit();
                    } else {
                        // Other error
                        error_log("Signup failed: " . $result['message']);
                        $_SESSION['error'] = $result['message'];
                        header("Location: signup.php");
                        exit();
                    }
                }
            } else {
                error_log("No email found in user info");
                $_SESSION['error'] = "Could not retrieve email from Google account.";
                header("Location: signup.php");
                exit();
            }
        } else {
            error_log("No access token in response: " . print_r($token_data, true));
            $_SESSION['error'] = "Failed to get access token from Google.";
            header("Location: signup.php");
            exit();
        }
    } catch (Exception $e) {
        error_log("Google auth error: " . $e->getMessage());
        error_log("Stack trace: " . $e->getTraceAsString());
        $_SESSION['error'] = "Authentication failed. Please try again.";
        header("Location: signup.php");
        exit();
    }
    error_log("=== Google OAuth Callback Ended ===");
} else {
    error_log("No authorization code received in callback");
    $_SESSION['error'] = "Authentication failed. Please try again.";
    header("Location: signup.php");
    exit();
}
?> 