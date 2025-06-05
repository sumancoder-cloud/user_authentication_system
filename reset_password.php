<?php
require_once 'config.php';
require_once 'email_handler.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Initialize response array
$response = ['success' => false, 'message' => ''];

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'request_reset':
            // Handle password reset request
            $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
            
            if (!$email) {
                $response['message'] = 'Please enter a valid email address.';
                break;
            }
            
            // Check if email exists in database
            $sql = "SELECT id FROM users WHERE email = ?";
            if ($stmt = mysqli_prepare($conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $email);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_store_result($stmt);
                
                if (mysqli_stmt_num_rows($stmt) === 0) {
                    $response['message'] = 'No account found with this email address.';
                    break;
                }
                
                // Generate OTP
                $otp = generateOTP();
                
                // Store OTP in database
                if (storeOTP($email, $otp, 'password_reset')) {
                    // Send OTP email
                    $emailHandler = new EmailHandler();
                    if ($emailHandler->sendOTPEmail($email, $otp, 'password_reset')) {
                        // Store email in session for security
                        $_SESSION['reset_email'] = $email;
                        $_SESSION['reset_time'] = time();
                        
                        $response['success'] = true;
                        $response['message'] = 'A verification code has been sent to your email.';
                    } else {
                        $response['message'] = 'Failed to send verification code. Please try again.';
                    }
                } else {
                    $response['message'] = 'Failed to process your request. Please try again.';
                }
            }
            break;
            
        case 'verify_otp':
            // Verify that user has gone through email verification
            if (!isset($_SESSION['reset_email']) || !isset($_SESSION['reset_time']) || 
                (time() - $_SESSION['reset_time']) > 600) { // 10 minutes expiry
                $response['message'] = 'Session expired. Please request a new verification code.';
                break;
            }
            
            // Handle OTP verification and password reset
            $email = $_SESSION['reset_email']; // Use email from session for security
            $otp = $_POST['otp'] ?? '';
            $new_password = $_POST['new_password'] ?? '';
            
            if (!$otp || !$new_password) {
                $response['message'] = 'All fields are required.';
                break;
            }
            
            // Validate password
            if (strlen($new_password) < 8) {
                $response['message'] = 'Password must be at least 8 characters long.';
                break;
            }
            
            // Verify OTP
            $sql = "SELECT id FROM otp_verification WHERE email = ? AND otp = ? AND purpose = 'password_reset' AND is_used = 0 AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            if ($stmt = mysqli_prepare($conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $email, $otp);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_store_result($stmt);
                
                if (mysqli_stmt_num_rows($stmt) === 0) {
                    $response['message'] = 'Invalid or expired verification code.';
                    break;
                }
                
                // Update password
                $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                $sql = "UPDATE users SET password = ? WHERE email = ?";
                if ($stmt = mysqli_prepare($conn, $sql)) {
                    mysqli_stmt_bind_param($stmt, "ss", $hashed_password, $email);
                    if (mysqli_stmt_execute($stmt)) {
                        // Mark OTP as used
                        $sql = "UPDATE otp_verification SET is_used = 1 WHERE email = ? AND otp = ? AND purpose = 'password_reset'";
                        if ($stmt = mysqli_prepare($conn, $sql)) {
                            mysqli_stmt_bind_param($stmt, "ss", $email, $otp);
                            mysqli_stmt_execute($stmt);
                        }
                        
                        // Clear reset session data
                        unset($_SESSION['reset_email']);
                        unset($_SESSION['reset_time']);
                        
                        $response['success'] = true;
                        $response['message'] = 'Password has been reset successfully. You can now login with your new password.';
                    } else {
                        $response['message'] = 'Failed to update password. Please try again.';
                    }
                }
            }
            break;
    }
    
    // If it's an AJAX request, send JSON response
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode($response);
        exit;
    }
}

// Check if user is trying to access OTP form directly without verification
$showOtpForm = isset($_SESSION['reset_email']) && isset($_SESSION['reset_time']) && 
               (time() - $_SESSION['reset_time']) <= 600; // 10 minutes expiry
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <!-- Prevent browser back/forward navigation -->
    <script>
        // Disable browser back/forward buttons
        history.pushState(null, null, location.href);
        window.onpopstate = function () {
            history.go(1);
        };
        
        // Prevent form resubmission on refresh
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
    <style>
        * {
            padding: 0;
            margin: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            background: radial-gradient(ellipse at top, #0f0c29 0%, #030116 40%, #01010aea 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-family: Arial, sans-serif;
        }

        .reset-container {
            position: relative;
            min-height: 350px;
            width: 400px;
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0px 0px 30px rgba(252, 249, 247, 0.1);
            padding: 30px 50px;
            color: white;
        }

        h2 {
            margin: 10px;
            text-align: center;
            color: orange;
        }

        .form-group {
            margin-bottom: 15px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="email"],
        input[type="password"],
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border-radius: 10px;
            height: 40px;
            background: #1a1a2e;
            box-shadow: inset 0 0 5px #333;
            color: white;
            border: 1px solid transparent;
        }

        input:focus {
            outline: none;
            border: 1px solid orange;
        }

        .password-container {
            position: relative;
        }

        .toggle-password {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #ccc;
            font-size: 18px;
        }

        .toggle-password:hover {
            color: orange;
        }

        button {
            width: 100%;
            height: 40px;
            border-radius: 20px;
            background-color: orange;
            border: none;
            cursor: pointer;
            font-weight: bold;
            font-size: 16px;
            color: white;
            transition: all 0.3s ease;
        }

        button:hover {
            background-color: #ff8c00;
            transform: translateY(-2px);
        }

        button:disabled {
            background-color: #666;
            cursor: not-allowed;
            transform: none;
        }

        .error-message {
            color: #ff4444;
            margin: 10px 0;
            text-align: center;
            display: none;
            padding: 10px;
            border-radius: 5px;
            background: rgba(255, 68, 68, 0.1);
        }

        .success-message {
            color: #00C851;
            margin: 10px 0;
            text-align: center;
            display: none;
            padding: 10px;
            border-radius: 5px;
            background: rgba(0, 200, 81, 0.1);
        }

        .otp-container {
            display: none;
        }

        .otp-inputs {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 15px 0;
        }

        .otp-inputs input {
            width: 40px;
            height: 40px;
            text-align: center;
            font-size: 20px;
        }

        .resend-timer {
            text-align: center;
            margin-top: 10px;
            color: #ccc;
        }

        .resend-timer a {
            color: orange;
            text-decoration: none;
        }

        .resend-timer a:hover {
            text-decoration: underline;
        }

        .back-link {
            text-align: center;
            margin-top: 15px;
        }

        .back-link a {
            color: orange;
            text-decoration: none;
        }

        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="reset-container">
        <!-- Request Reset Form -->
        <form id="requestResetForm" method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" style="display: <?php echo $showOtpForm ? 'none' : 'block'; ?>">
            <input type="hidden" name="action" value="request_reset">
            <h2>Reset Password</h2>
            <div class="error-message" id="requestError"></div>
            <div class="success-message" id="requestSuccess"></div>
            
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required 
                       placeholder="Enter your registered email">
            </div>
            
            <button type="submit" id="requestButton">Send Reset Code</button>
            
            <div class="back-link">
                <a href="<?php echo dirname($_SERVER['PHP_SELF']); ?>/login.php">Back to Login</a>
            </div>
        </form>

        <!-- OTP Verification Form -->
        <form id="otpForm" method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" style="display: <?php echo $showOtpForm ? 'block' : 'none'; ?>">
            <input type="hidden" name="action" value="verify_otp">
            <h2>Enter Verification Code</h2>
            <div class="error-message" id="otpError"></div>
            <div class="success-message" id="otpSuccess"></div>
            
            <div class="form-group">
                <label for="otp">Verification Code</label>
                <div class="otp-inputs">
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                    <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required>
                </div>
            </div>
            
            <div class="form-group">
                <label for="new_password">New Password</label>
                <div class="password-container">
                    <input type="password" id="new_password" name="new_password" required
                           placeholder="Enter new password" minlength="8">
                    <span class="toggle-password" onclick="togglePassword('new_password', this)">👁️</span>
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <div class="password-container">
                    <input type="password" id="confirm_password" name="confirm_password" required
                           placeholder="Confirm new password" minlength="8">
                    <span class="toggle-password" onclick="togglePassword('confirm_password', this)">👁️</span>
                </div>
            </div>
            
            <div class="resend-timer">
                Resend code in <span id="timer">60</span>s
            </div>
            
            <button type="submit" id="resetButton" disabled>Reset Password</button>
            
            <div class="back-link">
                <a href="#" onclick="showRequestForm()">Back to Email Form</a>
            </div>
        </form>
    </div>

    <script>
        // Toggle password visibility
        function togglePassword(inputId, toggleSpan) {
            const input = document.getElementById(inputId);
            if (input.type === "password") {
                input.type = "text";
                toggleSpan.textContent = "🙈";
            } else {
                input.type = "password";
                toggleSpan.textContent = "👁️";
            }
        }

        // Show request form
        function showRequestForm() {
            document.getElementById('requestResetForm').style.display = 'block';
            document.getElementById('otpForm').style.display = 'none';
            return false;
        }

        // Handle OTP input
        document.querySelectorAll('.otp-inputs input').forEach((input, index) => {
            input.addEventListener('input', function() {
                if (this.value.length === 1) {
                    if (index < 5) {
                        this.nextElementSibling.focus();
                    }
                }
                
                // Enable reset button if all OTP digits are entered
                const allFilled = Array.from(document.querySelectorAll('.otp-inputs input'))
                    .every(input => input.value.length === 1);
                document.getElementById('resetButton').disabled = !allFilled;
            });

            input.addEventListener('keydown', function(e) {
                if (e.key === 'Backspace' && !this.value && index > 0) {
                    this.previousElementSibling.focus();
                }
            });
        });

        // Handle request reset form submission
        document.getElementById('requestResetForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const button = document.getElementById('requestButton');
            const email = document.getElementById('email').value;
            
            button.disabled = true;
            button.textContent = 'Sending...';
            
            try {
                const response = await fetch('reset_password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: new URLSearchParams({
                        action: 'request_reset',
                        email: email
                    })
                });
                
                const data = await response.json();
                console.log('Response:', data);
                
                if (data.success) {
                    // Reload the page to show OTP form with session
                    window.location.reload();
                } else {
                    document.getElementById('requestError').textContent = data.message;
                    document.getElementById('requestError').style.display = 'block';
                    document.getElementById('requestSuccess').style.display = 'none';
                }
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('requestError').textContent = 'An error occurred. Please try again.';
                document.getElementById('requestError').style.display = 'block';
            } finally {
                button.disabled = false;
                button.textContent = 'Send Reset Code';
            }
        });

        // Handle OTP form submission
        document.getElementById('otpForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const button = document.getElementById('resetButton');
            const otp = Array.from(document.querySelectorAll('.otp-inputs input'))
                .map(input => input.value)
                .join('');
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (newPassword !== confirmPassword) {
                document.getElementById('otpError').textContent = 'Passwords do not match.';
                document.getElementById('otpError').style.display = 'block';
                return;
            }
            
            if (newPassword.length < 8) {
                document.getElementById('otpError').textContent = 'Password must be at least 8 characters long.';
                document.getElementById('otpError').style.display = 'block';
                return;
            }
            
            button.disabled = true;
            button.textContent = 'Resetting...';
            
            try {
                const response = await fetch('reset_password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: new URLSearchParams({
                        action: 'verify_otp',
                        otp: otp,
                        new_password: newPassword
                    })
                });
                
                const data = await response.json();
                console.log('OTP Response:', data);
                
                if (data.success) {
                    document.getElementById('otpSuccess').textContent = data.message;
                    document.getElementById('otpSuccess').style.display = 'block';
                    document.getElementById('otpError').style.display = 'none';
                    setTimeout(() => {
                        window.location.href = 'login.php';
                    }, 2000);
                } else {
                    document.getElementById('otpError').textContent = data.message;
                    document.getElementById('otpError').style.display = 'block';
                    document.getElementById('otpSuccess').style.display = 'none';
                }
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('otpError').textContent = 'An error occurred. Please try again.';
                document.getElementById('otpError').style.display = 'block';
            } finally {
                button.disabled = false;
                button.textContent = 'Reset Password';
            }
        });

        // Timer for resend
        function startTimer() {
            let timeLeft = 60;
            const timerSpan = document.getElementById('timer');
            const timer = setInterval(() => {
                timeLeft--;
                timerSpan.textContent = timeLeft;
                if (timeLeft <= 0) {
                    clearInterval(timer);
                    document.querySelector('.resend-timer').innerHTML = 
                        '<a href="#" onclick="resendOTP()" style="color: orange;">Resend code</a>';
                }
            }, 1000);
        }

        // Resend OTP
        async function resendOTP() {
            const email = document.getElementById('email').value;
            const button = document.getElementById('requestButton');
            
            button.disabled = true;
            button.textContent = 'Sending...';
            
            try {
                const response = await fetch('reset_password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        action: 'request_reset',
                        email: email
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('otpSuccess').textContent = 'A new code has been sent to your email.';
                    document.getElementById('otpSuccess').style.display = 'block';
                    document.getElementById('otpError').style.display = 'none';
                    startTimer();
                } else {
                    document.getElementById('otpError').textContent = data.message;
                    document.getElementById('otpError').style.display = 'block';
                    document.getElementById('otpSuccess').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('otpError').textContent = 'Failed to resend code. Please try again.';
                document.getElementById('otpError').style.display = 'block';
            } finally {
                button.disabled = false;
                button.textContent = 'Send Reset Code';
            }
        }

        // Add this to prevent form resubmission
        window.onload = function() {
            // Clear form data on page load
            document.getElementById('requestResetForm').reset();
            document.getElementById('otpForm').reset();
            
            // If OTP form is shown, focus on first input
            if (document.getElementById('otpForm').style.display === 'block') {
                document.querySelector('.otp-inputs input').focus();
            }
        };
    </script>
</body>
</html> 