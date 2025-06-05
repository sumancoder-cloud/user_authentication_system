<?php
require_once 'config.php';
require_once 'auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');

// Initialize response array
$response = ['success' => false, 'message' => ''];

// Check if OTP verification is required
if (!isset($_SESSION['temp_auth'])) {
    $response['message'] = 'Session expired. Please try again.';
    echo json_encode($response);
    exit();
}

// Handle OTP verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get OTP from input array and combine into single string
    $otpArray = $_POST['otp'] ?? [];
    $otp = implode('', $otpArray);
    $email = $_SESSION['temp_auth']['email'];
    $purpose = $_SESSION['temp_auth']['purpose'];

    if (empty($otp) || strlen($otp) !== 6) {
        $response['message'] = 'Please enter a valid 6-digit verification code';
    } else {
        // Initialize Auth class
        $auth = new Auth($conn);
        
        // Verify OTP
        $result = $auth->verifyOTP($email, $otp, $purpose);
        
        if ($result['success']) {
            // Clear temporary auth data
            unset($_SESSION['temp_auth']);
            
            // Set success message
            $_SESSION['success_message'] = $result['message'];
            
            $response['success'] = true;
            $response['message'] = $result['message'];
            
            // Add redirect URL based on purpose
            switch ($purpose) {
                case 'registration':
                    $response['redirect'] = 'welcome.php';
                    break;
                case 'login':
                    $response['redirect'] = 'welcome.php';
                    break;
                case 'password_reset':
                    $response['redirect'] = 'reset_password.php?token=' . $result['token'];
                    break;
                default:
                    $response['redirect'] = 'login.php';
            }
        } else {
            $response['message'] = $result['message'];
        }
    }
}

echo json_encode($response);
exit();
?> 