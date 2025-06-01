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
error_log("Process Role - Request Method: " . $_SERVER["REQUEST_METHOD"]);
error_log("Process Role - POST data: " . print_r($_POST, true));
error_log("Process Role - Session data: " . print_r($_SESSION, true));

// Check if role is selected
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['role'])) {
        error_log("Process Role - No role selected in POST data");
        $_SESSION['error'] = "Please select a role";
        header("Location: select_role.php");
        exit();
    }

    $selected_role = trim($_POST['role']);
    error_log("Process Role - Selected role: " . $selected_role);
    
    // Validate role
    if ($selected_role === 'user' || $selected_role === 'admin') {
        // Store selected role in session
        $_SESSION['selected_role'] = $selected_role;
        error_log("Process Role - Role stored in session: " . $_SESSION['selected_role']);
        
        // Redirect to signup page
        error_log("Process Role - Redirecting to signup.php");
        header("Location: signup.php");
        exit();
    } else {
        // Invalid role selected
        error_log("Process Role - Invalid role selected: " . $selected_role);
        $_SESSION['error'] = "Invalid role selected";
        header("Location: select_role.php");
        exit();
    }
} else {
    // Not a POST request
    error_log("Process Role - Invalid request method: " . $_SERVER["REQUEST_METHOD"]);
    $_SESSION['error'] = "Invalid request method";
    header("Location: select_role.php");
    exit();
}
?> 