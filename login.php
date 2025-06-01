<?php
require_once 'config.php';
require_once 'auth.php';

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Clear any existing session data when accessing login page
$_SESSION = array();

// Destroy the session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Destroy the session
session_destroy();

// Start a new session
session_start();

// Only redirect if explicitly logged in and not logging out
if (isset($_SESSION['user_id']) && isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true && !isset($_GET['logout'])) {
    header('Location: welcome.php');
    exit();
}

$selected_role = "";
$email = $password = "";
$email_err = $password_err = $role_err = $login_err = "";
$show_otp_form = false;

// Initialize Auth class
$auth = new Auth($conn);

// Debug: Check all users in database at login page load
error_log("=== Checking Database Users at Login Page Load ===");
$check_sql = "SELECT id, name, email, created_at FROM users";
$check_result = mysqli_query($conn, $check_sql);
if ($check_result) {
    error_log("Total users in database: " . mysqli_num_rows($check_result));
    while ($row = mysqli_fetch_assoc($check_result)) {
        error_log("Found user - ID: " . $row['id'] . ", Name: '" . $row['name'] . "', Email: '" . $row['email'] . "', Created: " . $row['created_at']);
    }
} else {
    error_log("Error checking users: " . mysqli_error($conn));
}
error_log("=== End of Database Check ===");

// Process login form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['login'])) {
        error_log("=== Login Attempt Started ===");
        error_log("POST data: " . print_r($_POST, true));

        // Validate role selection
        if (empty(trim($_POST["role"] ?? ''))) {
            $role_err = "Please select a role.";
            error_log("Login attempt - no role selected");
        } else {
            $selected_role = trim($_POST["role"]);
            error_log("Role selected: " . $selected_role);
        }

        // Validate username/email
        if (empty(trim($_POST["username_or_email"] ?? ''))) {
            $email_err = "Please enter your username or email.";
            error_log("Login attempt - empty username or email");
        } else {
            $email = trim($_POST["username_or_email"]);
            error_log("Username/Email provided: " . $email);
        }

        // Validate password
        if (empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter your password.";
            error_log("Login attempt - empty password");
        } else {
            $password = trim($_POST["password"]);
            error_log("Password provided (length: " . strlen($password) . ")");
        }
        
        // If no validation errors, proceed with login
        if (empty($email_err) && empty($password_err) && empty($role_err)) {
            error_log("Form validation passed, attempting login...");
            
            // Attempt to login with role check
            $result = $auth->login($email, $password, $selected_role);
            error_log("Login attempt result: " . print_r($result, true));
            
            if ($result['success']) {
                error_log("Login successful, checking session variables: " . print_r($_SESSION, true));
                if ($result['requires_otp']) {
                    // Store temporary data in session
                    $_SESSION['temp_auth'] = [
                        'email' => $email,
                        'purpose' => 'login'
                    ];
                    $show_otp_form = true;
                    error_log("Login OTP sent to: " . $email);
                } else {
                    error_log("Login successful without OTP, redirecting to welcome page");
                    // Redirect all users to welcome page
                    header("Location: welcome.php");
                    exit();
                }
            } else {
                $login_err = $result['message'];
                error_log("Login failed: " . $result['message']);
            }
        } else {
            error_log("Form validation failed - Role error: " . $role_err . ", Email error: " . $email_err . ", Password error: " . $password_err);
        }
        error_log("=== Login Attempt Ended ===");
    }
}

// Set page title
$page_title = "Login - Addwise";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo $page_title; ?></title>
    <link rel="stylesheet" href="form.css">
    <script>
        // Prevent back navigation and force reload
        (function() {
            // Store the current URL
            const currentUrl = window.location.href;
            
            // Function to force reload if URL changes
            function checkUrl() {
                if (window.location.href !== currentUrl) {
                    window.location.replace(currentUrl);
                }
            }

            // Check URL every 100ms
            setInterval(checkUrl, 100);

            // Handle all navigation attempts
            window.addEventListener('popstate', function(e) {
                window.location.replace(currentUrl);
            });

            // Prevent form resubmission
            if (window.history.replaceState) {
                window.history.replaceState(null, null, currentUrl);
            }

            // Disable backspace navigation
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Backspace' && !e.target.matches('input, textarea')) {
                    e.preventDefault();
                }
            });

            // Disable browser back/forward buttons
            window.addEventListener('beforeunload', function(e) {
                if (window.location.href !== currentUrl) {
                    e.preventDefault();
                    e.returnValue = '';
                    window.location.replace(currentUrl);
                }
            });

            // Override history methods
            const originalPushState = window.history.pushState;
            const originalReplaceState = window.history.replaceState;

            window.history.pushState = function() {
                originalPushState.apply(this, arguments);
                checkUrl();
            };

            window.history.replaceState = function() {
                originalReplaceState.apply(this, arguments);
                checkUrl();
            };

            // Clear browser history
            window.history.pushState(null, '', currentUrl);
            window.history.pushState(null, '', currentUrl);
            window.history.pushState(null, '', currentUrl);
        })();
    </script>
    <style>
        .form-container {
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            padding: 30px 40px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 400px;
        }
        
        .error-message, .success-message {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: none;
        }
        
        .error-message {
            color: #dc3545;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            display: block;
        }
        
        .success-message {
            color: #28a745;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            display: block;
        }
        
        .form-group {
            position: relative;
            margin-bottom: 20px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #1a1a2e;
            color: white;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            border-color: #ffcc00;
            outline: none;
            box-shadow: 0 0 0 2px rgba(255, 204, 0, 0.2);
        }
        
        .form-group input.valid {
            border-color: #28a745;
            background-color: rgba(40, 167, 69, 0.1);
        }
        
        .form-group input.invalid {
            border-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
        }
        
        .validation-icon {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 18px;
            display: none;
        }
        
        .validation-icon.valid {
            display: block;
            color: #28a745;
        }
        
        .validation-icon.invalid {
            display: block;
            color: #dc3545;
        }
        
        button[type="submit"] {
            width: 100%;
            padding: 12px;
            background: #ffcc00;
            color: black;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 20px;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        button[type="submit"]:hover {
            background: #fff;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        button[type="submit"]:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
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
            font-size: 18px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: #1a1a2e;
            color: white;
        }
        
        .otp-inputs input:focus {
            border-color: #ffcc00;
            outline: none;
        }
        
        .otp-inputs input.valid {
            border-color: #28a745;
            background-color: rgba(40, 167, 69, 0.1);
        }
        
        .otp-inputs input.invalid {
            border-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
        }
        
        .resend-timer {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin: 10px 0;
        }
        
        .back-link {
            text-align: center;
            margin-top: 10px;
        }
        
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
        }
        
        .back-link a:hover {
            text-decoration: underline;
        }
        
        .forgot-password {
            text-align: right;
            margin-top: -15px;
            margin-bottom: 15px;
        }
        
        .forgot-password a {
            color: #ffcc00;
            text-decoration: none;
            font-size: 14px;
        }
        
        .forgot-password a:hover {
            text-decoration: underline;
        }
        
        .role-container {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
        }
        
        .role-card {
            flex: 1;
            max-width: 200px;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid transparent;
            border-radius: 10px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .role-card:hover {
            transform: translateY(-5px);
            border-color: #ffcc00;
        }
        
        .role-card.selected {
            border-color: #ffcc00;
            background: rgba(255, 204, 0, 0.1);
        }
        
        .role-card input[type="radio"] {
            display: none;
        }
        
        .role-icon {
            font-size: 2em;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .role-title {
            font-size: 1.2em;
            font-weight: bold;
            color: #ffcc00;
            text-align: center;
            margin-bottom: 10px;
        }
        
        .role-description {
            font-size: 0.9em;
            color: #fff;
            text-align: center;
        }
        
        .error-message.role-error {
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="loginForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" 
              style="display: <?php echo $show_otp_form ? 'none' : 'block'; ?>">
            <h2>Login to Addwise</h2>
            
            <?php if (isset($_SESSION['success'])): ?>
                <div class="success-message">
                    <?php 
                    echo $_SESSION['success'];
                    unset($_SESSION['success']);
                    ?>
                </div>
            <?php endif; ?>

            <?php if (isset($_SESSION['error'])): ?>
                <div class="error-message">
                    <?php 
                    echo $_SESSION['error'];
                    unset($_SESSION['error']);
                    ?>
                </div>
            <?php endif; ?>

            <div class="error-message" style="display: <?php echo !empty($login_err) ? 'block' : 'none'; ?>">
                <?php echo $login_err; ?>
            </div>
            <div class="error-message role-error" style="display: <?php echo !empty($role_err) ? 'block' : 'none'; ?>">
                <?php echo $role_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($email_err) ? 'block' : 'none'; ?>">
                <?php echo $email_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($password_err) ? 'block' : 'none'; ?>">
                <?php echo $password_err; ?>
            </div>

            <div class="role-container">
                <div class="role-card" onclick="selectRole('user')">
                    <input type="radio" name="role" id="role_user" value="user" required>
                    <label for="role_user">
                        <div class="role-icon">👤</div>
                        <div class="role-title">User</div>
                        <div class="role-description">
                            Login as a regular user to access your account and services.
                        </div>
                    </label>
                </div>
                
                <div class="role-card" onclick="selectRole('admin')">
                    <input type="radio" name="role" id="role_admin" value="admin" required>
                    <label for="role_admin">
                        <div class="role-icon">👨‍💼</div>
                        <div class="role-title">Admin</div>
                        <div class="role-description">
                            Login as an administrator to access the admin dashboard.
                            Requires admin credentials.
                        </div>
                    </label>
                </div>
            </div>

            <div class="form-group">
                <label for="username_or_email">Username or Email</label>
                <input type="text" id="username_or_email" name="username_or_email" required 
                       value="<?php echo $email; ?>"
                       title="Enter your username or email address">
                <span class="validation-icon" id="usernameOrEmailIcon"></span>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
                <span class="validation-icon" id="passwordIcon"></span>
            </div>

            <div class="forgot-password">
                <a href="reset_password.php">Forgot Password?</a>
            </div>

            <button type="submit" name="login" id="loginButton" disabled>Login</button>

            <p class="switch">Don't have an account? <a href="signup.php">Sign Up</a></p>
        </form>

        <form id="otpForm" class="otp-container" action="verify_otp.php" method="post"
              style="display: <?php echo $show_otp_form ? 'block' : 'none'; ?>"
              onsubmit="return handleOTPSubmit(event)">
            <h2>Enter Verification Code</h2>
            
            <div id="otpError" class="error-message" style="display: none;"></div>
            <div id="otpSuccess" class="success-message" style="display: none;"></div>

            <p style="text-align: center; color: #666; margin-bottom: 15px;">
                We've sent a verification code to <?php echo htmlspecialchars($email); ?>
            </p>

            <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">

            <div class="otp-inputs">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
            </div>

            <div id="otpValidationStatus" class="otp-validation-status"></div>

            <button type="submit" name="verify_otp" id="verifyButton" disabled>Verify Code</button>

            <div class="resend-timer">
                Resend code in <span id="timer">60</span>s
            </div>

            <div class="back-link">
                <a href="#" onclick="return showLoginForm()">Back to login</a>
            </div>
        </form>
    </div>

    <script>
        // Add debug mode
        const DEBUG = true;

        function logDebug(...args) {
            if (DEBUG) {
                console.log('[DEBUG]', ...args);
            }
        }

        function validateUsernameOrEmail(input) {
            const value = input.value.trim();
            const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            const isUsername = /^[a-zA-Z0-9_]{3,20}$/.test(value);
            
            if (value === '') {
                input.classList.remove('valid', 'invalid');
                document.getElementById('usernameOrEmailIcon').style.display = 'none';
                return false;
            }
            
            if (isEmail || isUsername) {
                input.classList.add('valid');
                input.classList.remove('invalid');
                const icon = document.getElementById('usernameOrEmailIcon');
                icon.style.display = 'block';
                icon.classList.add('valid');
                icon.classList.remove('invalid');
                icon.textContent = '✓';
                return true;
            } else {
                input.classList.add('invalid');
                input.classList.remove('valid');
                const icon = document.getElementById('usernameOrEmailIcon');
                icon.style.display = 'block';
                icon.classList.add('invalid');
                icon.classList.remove('valid');
                icon.textContent = '✕';
                return false;
            }
        }

        function validatePassword(input) {
            const value = input.value;
            const isValid = value.length >= 8;
            
            if (value === '') {
                input.classList.remove('valid', 'invalid');
                document.getElementById('passwordIcon').style.display = 'none';
                return false;
            }
            
            input.classList.remove('valid', 'invalid');
            const icon = document.getElementById('passwordIcon');
            icon.style.display = 'block';
            
            if (isValid) {
                input.classList.add('valid');
                icon.classList.add('valid');
                icon.classList.remove('invalid');
                icon.textContent = '✓';
            } else {
                input.classList.add('invalid');
                icon.classList.add('invalid');
                icon.classList.remove('valid');
                icon.textContent = '✕';
            }
            
            validateForm();
            return isValid;
        }

        function validateForm() {
            const usernameOrEmail = document.getElementById('username_or_email');
            const password = document.getElementById('password');
            const role = document.querySelector('input[name="role"]:checked');
            
            const isUsernameOrEmailValid = usernameOrEmail.classList.contains('valid');
            const isPasswordValid = password.classList.contains('valid');
            const isRoleSelected = role !== null;
            
            const loginButton = document.getElementById('loginButton');
            loginButton.disabled = !(isUsernameOrEmailValid && isPasswordValid && isRoleSelected);
        }

        function validateOTPInput(input) {
            const value = input.value.trim();
            const isValid = /^[0-9]$/.test(value);
            
            input.classList.remove('valid', 'invalid');
            
            if (value.length === 1) {
                if (isValid) {
                    input.classList.add('valid');
                const nextInput = input.nextElementSibling;
                if (nextInput) {
                    nextInput.focus();
                    }
                } else {
                    input.classList.add('invalid');
                    input.value = '';
                }
            }
            
            updateOTPValidationStatus();
        }

        function updateOTPValidationStatus() {
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            const validationStatus = document.getElementById('otpValidationStatus');
            const filledInputs = Array.from(otpInputs).filter(input => input.value.length === 1).length;
            
            if (filledInputs === 0) {
                validationStatus.textContent = 'Enter the 6-digit verification code';
                validationStatus.className = 'otp-validation-status';
            } else if (filledInputs < 6) {
                validationStatus.textContent = `Enter ${6 - filledInputs} more digit${6 - filledInputs === 1 ? '' : 's'}`;
                validationStatus.className = 'otp-validation-status';
            } else {
                const allValid = Array.from(otpInputs).every(input => 
                    input.value.length === 1 && input.classList.contains('valid')
                );
                if (allValid) {
                    validationStatus.textContent = 'Verification code is valid';
                    validationStatus.className = 'otp-validation-status valid';
                    document.getElementById('verifyButton').disabled = false;
                } else {
                    validationStatus.textContent = 'Please enter valid digits only';
                    validationStatus.className = 'otp-validation-status invalid';
                    document.getElementById('verifyButton').disabled = true;
                }
            }
        }

        function handleOTPSubmit(event) {
            event.preventDefault();
            
            const form = document.getElementById('otpForm');
            const submitButton = document.getElementById('verifyButton');
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            
            // Clear previous messages
            document.getElementById('otpError').style.display = 'none';
            document.getElementById('otpSuccess').style.display = 'none';
            
            // Validate all inputs
            let otp = [];
            let isValid = true;
            
            otpInputs.forEach((input, index) => {
                const value = input.value.trim();
                if (!value || !/^[0-9]$/.test(value)) {
                    isValid = false;
                    input.classList.add('invalid');
                } else {
                    input.classList.add('valid');
                    otp.push(value);
                }
            });

            if (!isValid || otp.length !== 6) {
                showError('Please enter a valid 6-digit verification code');
                return false;
            }

            // Show loading state
            submitButton.disabled = true;
            submitButton.classList.add('verifying');
            submitButton.textContent = 'Verifying...';
            
            // Create FormData object
            const formData = new FormData();
            const email = form.querySelector('input[name="email"]').value;
            formData.append('email', email);
            otp.forEach((digit, index) => {
                formData.append('otp[]', digit);
            });

            // Submit form using fetch
            fetch('verify_otp.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                console.log('Verification response:', data);
                
                submitButton.classList.remove('verifying');
                
                if (data.success) {
                    showSuccess(data.message || 'Login successful!');
                    otpInputs.forEach(input => {
                        input.disabled = true;
                        input.classList.add('valid');
                    });
                    submitButton.style.display = 'none';
                    
                    // Redirect to welcome page after successful verification
                    setTimeout(() => {
                        window.location.href = 'welcome.php';
                    }, 1500);
                } else {
                    showError(data.message || 'Invalid verification code. Please try again.');
                    submitButton.disabled = false;
                    submitButton.textContent = 'Verify Code';
                    resetOTPInputs();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                submitButton.classList.remove('verifying');
                showError('Something went wrong. Please try again.');
                submitButton.disabled = false;
                submitButton.textContent = 'Verify Code';
            });

            return false;
        }

        function showError(message) {
            const errorDiv = document.getElementById('otpError');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            document.getElementById('otpSuccess').style.display = 'none';
            
            if (DEBUG) {
                logDebug('Showing error message:', message);
            }
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('otpSuccess');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
            document.getElementById('otpError').style.display = 'none';
            
            if (DEBUG) {
                logDebug('Showing success message:', message);
            }
        }

        function resetOTPInputs() {
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            otpInputs.forEach(input => {
                input.value = '';
                input.disabled = false;
                input.classList.remove('valid', 'invalid');
            });
            otpInputs[0].focus();
            
            document.getElementById('otpError').style.display = 'none';
            document.getElementById('otpSuccess').style.display = 'none';
            document.getElementById('otpValidationStatus').textContent = 'Enter the 6-digit verification code';
            document.getElementById('otpValidationStatus').className = 'otp-validation-status';
            
            const verifyButton = document.getElementById('verifyButton');
            verifyButton.disabled = true;
            verifyButton.textContent = 'Verify Code';
            verifyButton.style.display = 'block';
        }

        function showLoginForm() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('otpForm').style.display = 'none';
            return false;
        }

        // Start timer if OTP form is shown
        if (document.getElementById('otpForm').style.display === 'block') {
            let timeLeft = 60;
            const timerSpan = document.getElementById('timer');
            const timer = setInterval(() => {
                timeLeft--;
                timerSpan.textContent = timeLeft;
                if (timeLeft <= 0) {
                    clearInterval(timer);
                    document.querySelector('.resend-timer').innerHTML = 
                        '<a href="#" onclick="resendOTP()" style="color: #ffcc00; text-decoration: none;">Resend code</a>';
                }
            }, 1000);
            document.querySelector('.otp-inputs input').focus();
        }

        // Add event listeners for input validation
        document.addEventListener('DOMContentLoaded', function() {
            const usernameOrEmailInput = document.getElementById('username_or_email');
            const passwordInput = document.getElementById('password');
            
            usernameOrEmailInput.addEventListener('input', function() {
                validateUsernameOrEmail(this);
            });
            
            passwordInput.addEventListener('input', function() {
                validatePassword(this);
            });
            
            // Initial validation if there are values
            if (usernameOrEmailInput.value) {
                validateUsernameOrEmail(usernameOrEmailInput);
            }
            if (passwordInput.value) {
                validatePassword(passwordInput);
            }
        });

        if (DEBUG) {
            logDebug('Page loaded');
            logDebug('Session status:', '<?php echo isset($_SESSION['temp_auth']) ? 'Active' : 'Expired'; ?>');
            logDebug('Email:', '<?php echo htmlspecialchars($email); ?>');
        }

        function selectRole(role) {
            // Remove selected class from all role cards
            document.querySelectorAll('.role-card').forEach(card => {
                card.classList.remove('selected');
            });
            
            // Add selected class to clicked role card
            const selectedCard = document.querySelector(`.role-card[onclick="selectRole('${role}')"]`);
            selectedCard.classList.add('selected');
            
            // Set the radio button value
            document.getElementById(`role_${role}`).checked = true;
            
            // Validate form
            validateForm();
        }

        // Add role validation to the form submission
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const role = document.querySelector('input[name="role"]:checked');
            const email = document.getElementById('username_or_email').value;
            
            if (!role) {
                e.preventDefault();
                alert('Please select a role');
                return;
            }
            
            // Additional validation for admin login
            if (role.value === 'admin') {
                if (email === 'sumanyadav_tati@srmap.edu.in') {
                    // Allow this specific email
                } else if (!email.endsWith('@srmap.edu.in')) {
                    e.preventDefault();
                    alert('Admin access is restricted to authorized email domains.');
                    return;
                }
            }
        });
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 