<?php
require_once 'config.php';
require_once 'auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');

$response = ['success' => false, 'message' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $purpose = $_SESSION['temp_auth']['purpose'] ?? 'registration';

    if (empty($email)) {
        $response['message'] = 'Email is required';
    } else {
        // Initialize Auth class
        $auth = new Auth($conn);
        
        // Generate and send new OTP
        $result = $auth->generateAndSendOTP($email, $purpose);
        
        if ($result['success']) {
            $response['success'] = true;
            $response['message'] = 'A new verification code has been sent to your email';
        } else {
            $response['message'] = $result['message'];
        }
    }
}

echo json_encode($response);
exit();
?> 