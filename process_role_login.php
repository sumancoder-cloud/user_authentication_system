<?php
require_once 'config.php';
require_once 'auth.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Debug logging
error_log("Process Role Login - Request Method: " . $_SERVER["REQUEST_METHOD"]);
error_log("Process Role Login - POST data: " . print_r($_POST, true));
error_log("Process Role Login - Session data: " . print_r($_SESSION, true));

// Check if role is selected
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['role'])) {
        error_log("Process Role Login - No role selected in POST data");
        $_SESSION['error'] = "Please select a role";
        header("Location: select_role_login.php");
        exit();
    }

    $selected_role = trim($_POST['role']);
    error_log("Process Role Login - Selected role: " . $selected_role);
    
    // Validate role
    if ($selected_role === 'user' || $selected_role === 'admin') {
        // Store selected role in session
        $_SESSION['selected_role'] = $selected_role;
        error_log("Process Role Login - Role stored in session: " . $_SESSION['selected_role']);
        
        // Redirect to login page
        error_log("Process Role Login - Redirecting to login.php");
        header("Location: login.php");
        exit();
    } else {
        // Invalid role selected
        error_log("Process Role Login - Invalid role selected: " . $selected_role);
        $_SESSION['error'] = "Invalid role selected";
        header("Location: select_role_login.php");
        exit();
    }
} else {
    // Not a POST request
    error_log("Process Role Login - Invalid request method: " . $_SERVER["REQUEST_METHOD"]);
    $_SESSION['error'] = "Invalid request method";
    header("Location: select_role_login.php");
    exit();
}
?> 