<?php
require_once 'email_handler.php';

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Test email sending
$emailHandler = new EmailHandler();
$test_email = 'suman.tati2005@gmail.com'; // Your email address
$test_otp = '123456'; // Test OTP

echo "Attempting to send test email to: " . $test_email . "\n";

try {
    $result = $emailHandler->sendOTP($test_email, $test_otp, 'registration');
    if ($result) {
        echo "Test email sent successfully!\n";
        echo "Please check your email (including spam folder) for the test OTP.\n";
    } else {
        echo "Failed to send test email.\n";
        echo "Check the PHP error log for details.\n";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Stack trace: " . $e->getTraceAsString() . "\n";
}
?> 