<?php
require_once 'config.php';
require_once 'auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if user is in registration process
if (!isset($_SESSION['temp_auth']) || $_SESSION['temp_auth']['purpose'] !== 'registration') {
    header("Location: signup.php");
    exit();
}

$email = $_SESSION['temp_auth']['email'];
$error_message = '';
$success_message = '';

// Handle OTP verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['verify_otp'])) {
        // Get OTP from input array and combine into single string
        $otpArray = $_POST['otp'] ?? [];
        $otp = implode('', $otpArray);
        
        if (empty($otp) || strlen($otp) !== 6) {
            $error_message = 'Please enter a valid 6-digit verification code';
        } else {
            // Initialize Auth class
            $auth = new Auth($conn);
            
            // Verify OTP
            $result = $auth->verifyOTP($email, $otp, 'registration');
            
            if ($result['success']) {
                // Store success message in session
                $_SESSION['success_message'] = $result['message'];
                
                // Redirect to login page
                header("Location: login.php");
                exit();
            } else {
                $error_message = $result['message'];
            }
        }
    } elseif (isset($_POST['resend_otp'])) {
        // Initialize Auth class
        $auth = new Auth($conn);
        
        // Generate and send new OTP
        $result = $auth->generateAndSendOTP($email, 'registration');
        
        if ($result['success']) {
            $success_message = 'A new verification code has been sent to your email';
        } else {
            $error_message = $result['message'];
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Email - Addwise</title>
    <link rel="stylesheet" href="form.css">
    <style>
        .otp-container {
            max-width: 400px;
            margin: 50px auto;
            padding: 30px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        
        .otp-inputs {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
        }
        
        .otp-inputs input {
            width: 50px;
            height: 50px;
            text-align: center;
            font-size: 24px;
            border: 2px solid #ddd;
            border-radius: 8px;
            margin: 0 5px;
            background: #1a1a2e;
            color: white;
        }
        
        .otp-inputs input:focus {
            border-color: #4CAF50;
            outline: none;
        }
        
        .error-message {
            color: #dc3545;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: <?php echo !empty($error_message) ? 'block' : 'none'; ?>;
        }
        
        .success-message {
            color: #155724;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: <?php echo !empty($success_message) ? 'block' : 'none'; ?>;
        }
        
        .verify-button {
            width: 100%;
            padding: 12px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .verify-button:hover {
            background: #45a049;
        }
        
        .resend-button {
            width: 100%;
            padding: 12px;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
            margin-top: 10px;
        }
        
        .resend-button:hover {
            background: #5a6268;
        }
        
        .email-display {
            color: #666;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="otp-container">
        <h2>Verify Your Email</h2>
        
        <div class="email-display">
            Enter the verification code sent to:<br>
            <strong><?php echo htmlspecialchars($email); ?></strong>
        </div>
        
        <div class="error-message">
            <?php echo htmlspecialchars($error_message); ?>
        </div>
        
        <div class="success-message">
            <?php echo htmlspecialchars($success_message); ?>
        </div>
        
        <form method="post" id="otpForm">
            <div class="otp-inputs">
                <?php for($i = 1; $i <= 6; $i++): ?>
                    <input type="text" 
                           name="otp[]" 
                           maxlength="1" 
                           pattern="[0-9]" 
                           inputmode="numeric" 
                           required 
                           autocomplete="off"
                           onkeyup="moveToNext(this, <?php echo $i; ?>)"
                           onkeydown="handleBackspace(this, <?php echo $i; ?>)">
                <?php endfor; ?>
            </div>
            
            <button type="submit" name="verify_otp" class="verify-button">Verify Email</button>
            <button type="submit" name="resend_otp" class="resend-button">Resend Code</button>
        </form>
    </div>

    <script>
        function moveToNext(input, currentIndex) {
            if (input.value.length === 1) {
                if (currentIndex < 6) {
                    const nextInput = input.parentElement.children[currentIndex];
                    nextInput.focus();
                }
            }
        }
        
        function handleBackspace(input, currentIndex) {
            if (event.key === 'Backspace' && input.value.length === 0) {
                if (currentIndex > 1) {
                    const prevInput = input.parentElement.children[currentIndex - 2];
                    prevInput.focus();
                }
            }
        }
        
        // Auto-focus first input on page load
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelector('.otp-inputs input').focus();
        });
        
        // Handle paste event
        document.querySelector('.otp-inputs').addEventListener('paste', function(e) {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const numbers = pastedData.replace(/[^0-9]/g, '').split('').slice(0, 6);
            
            const inputs = this.querySelectorAll('input');
            numbers.forEach((num, index) => {
                if (inputs[index]) {
                    inputs[index].value = num;
                }
            });
            
            if (numbers.length === 6) {
                document.querySelector('button[name="verify_otp"]').focus();
            } else if (inputs[numbers.length]) {
                inputs[numbers.length].focus();
            }
        });
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 