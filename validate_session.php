<?php
require_once 'config.php';
require_once 'security.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Get POST data
$data = json_decode(file_get_contents('php://input'), true);
$token = $data['token'] ?? '';

// Prepare response
$response = [
    'valid' => false,
    'redirect' => 'login.php'
];

// Validate session and token
if (isset($_SESSION['user_id']) && 
    isset($_SESSION['logged_in']) && 
    $_SESSION['logged_in'] === true && 
    isset($_SESSION['page_token']) && 
    $token === $_SESSION['page_token']) {
    
    $response['valid'] = true;
    $response['redirect'] = $_SESSION['last_page'] ?? 'welcome.php';
}

// Send JSON response
header('Content-Type: application/json');
echo json_encode($response);
?> 