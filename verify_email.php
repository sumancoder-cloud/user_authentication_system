<?php
require_once 'config.php';
require_once 'auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$verification_status = '';
$verification_message = '';

if (isset($_GET['token'])) {
    $token = trim($_GET['token']);
    
    // Initialize Auth class
    $auth = new Auth($conn);
    
    // Verify the token
    $result = $auth->verifyEmailToken($token);
    
    if ($result['success']) {
        $verification_status = 'success';
        $verification_message = 'Your email has been verified successfully! You can now login to your account.';
        
        // Store success message in session
        $_SESSION['success_message'] = $verification_message;
        
        // Redirect to login page after 3 seconds
        header("refresh:3;url=login.php");
    } else {
        $verification_status = 'error';
        $verification_message = $result['message'];
    }
} else {
    $verification_status = 'error';
    $verification_message = 'Invalid verification link.';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - Addwise</title>
    <link rel="stylesheet" href="form.css">
    <style>
        .verification-container {
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            text-align: center;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        
        .verification-status {
            font-size: 24px;
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 8px;
        }
        
        .verification-status.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .verification-status.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .verification-message {
            margin-bottom: 20px;
            line-height: 1.6;
        }
        
        .redirect-message {
            font-size: 14px;
            color: #666;
            margin-top: 20px;
        }
        
        .login-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        
        .login-link:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="verification-container">
        <div class="verification-status <?php echo $verification_status; ?>">
            <?php echo $verification_status === 'success' ? '✓ Verification Successful' : '✕ Verification Failed'; ?>
        </div>
        
        <div class="verification-message">
            <?php echo htmlspecialchars($verification_message); ?>
        </div>
        
        <?php if ($verification_status === 'success'): ?>
            <div class="redirect-message">
                You will be redirected to the login page in a few seconds...
            </div>
            <a href="login.php" class="login-link">Go to Login</a>
        <?php else: ?>
            <a href="login.php" class="login-link">Back to Login</a>
        <?php endif; ?>
    </div>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 