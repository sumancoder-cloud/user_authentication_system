<?php
require_once 'config.php';
require_once 'auth.php';
require_once 'google_auth.php';

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if role is selected
if (!isset($_SESSION['selected_role'])) {
    header("Location: select_role.php");
    exit();
}

$selected_role = $_SESSION['selected_role'];
$name = $username = $email = $password = $confirm_password = "";
$name_err = $username_err = $email_err = $password_err = $confirm_password_err = $signup_err = "";

// Initialize Auth class
$auth = new Auth($conn);

// Initialize Google Auth
$google_auth = new GoogleAuth();
$google_auth_url = $google_auth->getAuthUrl();

// Set google_auth_started flag when generating the auth URL
$_SESSION['google_auth_started'] = true;

// Process signup form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['signup'])) {
        error_log("=== Signup Attempt Started ===");
        error_log("POST data: " . print_r($_POST, true));

        // Validate name
        if (empty(trim($_POST["name"] ?? ''))) {
            $name_err = "Please enter your name.";
            error_log("Signup attempt - empty name");
        } else {
            $name = trim($_POST["name"]);
            error_log("Name provided: " . $name);
        }

        // Validate username
        if (empty(trim($_POST["username"] ?? ''))) {
            $username_err = "Please enter a username.";
            error_log("Signup attempt - empty username");
        } else {
            $username = trim($_POST["username"]);
            error_log("Username provided: " . $username);
        }

        // Validate email
        if (empty(trim($_POST["email"] ?? ''))) {
            $email_err = "Please enter your email.";
            error_log("Signup attempt - empty email");
        } else {
            $email = trim($_POST["email"]);
            error_log("Email provided: " . $email);
        }

        // Validate password
        if (empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter a password.";
            error_log("Signup attempt - empty password");
        } else {
            $password = trim($_POST["password"]);
            error_log("Password provided (length: " . strlen($password) . ")");
        }

        // Validate confirm password
        if (empty(trim($_POST["confirm_password"] ?? ''))) {
            $confirm_password_err = "Please confirm your password.";
            error_log("Signup attempt - empty confirm password");
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if ($password !== $confirm_password) {
                $confirm_password_err = "Passwords do not match.";
                error_log("Signup attempt - passwords do not match");
            }
        }

        // Additional validation for admin signup
        if ($selected_role === 'admin') {
            if ($email === 'sumanyadav_tati@srmap.edu.in') {
                // Allow this specific email
            } else if (!preg_match('/@srmap\.edu\.in$/', $email)) {
                $email_err = "Admin accounts must use an authorized email domain.";
                error_log("Signup attempt - invalid admin email domain");
            }
        }
        
        // If no validation errors, proceed with signup
        if (empty($name_err) && empty($username_err) && empty($email_err) && 
            empty($password_err) && empty($confirm_password_err)) {
            error_log("Form validation passed, attempting signup...");
            
            // Attempt to register with role
            $result = $auth->register($name, $username, $email, $password, $selected_role);
            error_log("Signup attempt result: " . print_r($result, true));
            
            if ($result['success']) {
                // Store temporary data in session for OTP verification
                $_SESSION['temp_auth'] = [
                    'email' => $email,
                    'purpose' => 'registration'
                ];
                header("Location: enter_otp.php");
                exit();
            } else {
                $signup_err = $result['message'];
                error_log("Signup failed: " . $result['message']);
            }
        } else {
            error_log("Form validation failed - Name error: " . $name_err . 
                     ", Username error: " . $username_err . 
                     ", Email error: " . $email_err . 
                     ", Password error: " . $password_err . 
                     ", Confirm password error: " . $confirm_password_err);
        }
        error_log("=== Signup Attempt Ended ===");
    }
}

// Set page title based on role
$page_title = ucfirst($selected_role) . " Signup";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo $page_title; ?> - Addwise</title>
    <link rel="stylesheet" href="form.css">
    <style>
        .form-container {
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            padding: 30px 40px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 500px;
        }
        
        .error-message {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: none;
            color: #dc3545;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
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
        
        .role-badge {
            background: #f0f4ff;
            color: #667eea;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            display: inline-block;
            margin-bottom: 20px;
        }

        .role-badge.admin {
            background: #fff0f4;
            color: #e6677e;
        }

        .change-role {
            color: #667eea;
            text-decoration: none;
            font-size: 0.9em;
            display: inline-block;
            margin-top: 10px;
            transition: all 0.3s ease;
        }

        .change-role:hover {
            color: #5a6fd6;
            text-decoration: underline;
        }

        .password-requirements {
            font-size: 0.8em;
            color: #666;
            margin-top: 5px;
            padding-left: 10px;
        }

        .password-requirements ul {
            list-style: none;
            padding-left: 0;
            margin-top: 5px;
        }

        .password-requirements li {
            margin-bottom: 3px;
            display: flex;
            align-items: center;
        }

        .password-requirements li::before {
            content: "•";
            margin-right: 5px;
            color: #666;
        }

        .password-requirements li.valid::before {
            content: "✓";
            color: #28a745;
        }

        .password-requirements li.invalid::before {
            content: "✕";
            color: #dc3545;
        }

        .social-signup {
            margin: 20px 0;
            text-align: center;
        }
        
        .social-signup .divider {
            display: flex;
            align-items: center;
            text-align: center;
            margin: 20px 0;
            color: #666;
        }
        
        .social-signup .divider::before,
        .social-signup .divider::after {
            content: '';
            flex: 1;
            border-bottom: 1px solid #ddd;
        }
        
        .social-signup .divider span {
            padding: 0 10px;
        }
        
        .google-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 12px;
            background: #fff;
            color: #757575;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            margin-bottom: 15px;
        }
        
        .google-btn:hover {
            background: #f5f5f5;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .google-btn img {
            width: 18px;
            height: 18px;
            margin-right: 10px;
        }

        .google-signin-button {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 12px;
            background: #fff;
            color: #757575;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 20px;
            font-size: 16px;
            text-decoration: none;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .google-signin-button:hover {
            background: #f8f8f8;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }

        .google-icon {
            width: 18px;
            height: 18px;
            margin-right: 10px;
        }

        .divider {
            display: flex;
            align-items: center;
            text-align: center;
            margin: 20px 0;
            color: #666;
        }

        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            border-bottom: 1px solid #ddd;
        }

        .divider span {
            padding: 0 10px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="signupForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <h2>Create <?php echo ucfirst($selected_role); ?> Account</h2>
            
            <div class="role-badge <?php echo $selected_role; ?>">
                <?php echo ucfirst($selected_role); ?> Account
            </div>
            
            <div class="error-message" style="display: <?php echo !empty($signup_err) ? 'block' : 'none'; ?>">
                <?php echo $signup_err; ?>
            </div>

            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" required 
                       value="<?php echo htmlspecialchars($name); ?>"
                       onkeyup="validateName(this)">
                <span class="validation-icon" id="nameIcon"></span>
            </div>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       value="<?php echo htmlspecialchars($username); ?>"
                       onkeyup="validateUsername(this)">
                <span class="validation-icon" id="usernameIcon"></span>
            </div>

            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required 
                       value="<?php echo htmlspecialchars($email); ?>"
                       onkeyup="validateEmail(this)">
                <span class="validation-icon" id="emailIcon"></span>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required
                       onkeyup="validatePassword(this)">
                <span class="validation-icon" id="passwordIcon"></span>
                <div class="password-requirements">
                    <ul>
                        <li id="length">At least 8 characters</li>
                        <li id="uppercase">One uppercase letter</li>
                        <li id="lowercase">One lowercase letter</li>
                        <li id="number">One number</li>
                        <li id="special">One special character</li>
                    </ul>
                </div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       onkeyup="validateConfirmPassword(this)">
                <span class="validation-icon" id="confirmPasswordIcon"></span>
            </div>

            <button type="submit" name="signup" id="signupButton" disabled>Create Account</button>

            <div class="divider">
                <span>OR</span>
            </div>

            <a href="<?php echo $google_auth_url; ?>" class="google-signin-button">
                <svg class="google-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                </svg>
                Sign up with Google
            </a>

            <p class="switch">Already have an account? <a href="login.php">Login</a></p>
            <a href="select_role.php" class="change-role">Change Role</a>
        </form>
    </div>

    <script>
        // Add debug mode
        const DEBUG = true;

        // Strict navigation prevention
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
        })();

        function logDebug(...args) {
            if (DEBUG) {
                console.log('[DEBUG]', ...args);
            }
        }

        function validateName(input) {
            const value = input.value.trim();
            const isValid = value.length >= 2 && /^[a-zA-Z ]*$/.test(value);
            
            updateValidationUI(input, 'nameIcon', isValid);
            validateForm();
            return isValid;
        }

        function validateUsername(input) {
            const value = input.value.trim();
            const isValid = /^[a-zA-Z0-9_]{3,20}$/.test(value);
            
            updateValidationUI(input, 'usernameIcon', isValid);
            validateForm();
            return isValid;
        }

        function validateEmail(input) {
            const value = input.value.trim();
            const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            
            // Additional validation for admin email
            if (isValid && '<?php echo $selected_role; ?>' === 'admin') {
                const isAdminEmail = value === 'sumanyadav_tati@srmap.edu.in' || value.endsWith('@srmap.edu.in');
                updateValidationUI(input, 'emailIcon', isAdminEmail);
                validateForm();
                return isAdminEmail;
            }
            
            updateValidationUI(input, 'emailIcon', isValid);
            validateForm();
            return isValid;
        }

        function validatePassword(input) {
            const value = input.value;
            const requirements = {
                length: value.length >= 8,
                uppercase: /[A-Z]/.test(value),
                lowercase: /[a-z]/.test(value),
                number: /[0-9]/.test(value),
                special: /[^A-Za-z0-9]/.test(value)
            };
            
            // Update requirement indicators
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(req);
                if (requirements[req]) {
                    element.classList.add('valid');
                    element.classList.remove('invalid');
                } else {
                    element.classList.add('invalid');
                    element.classList.remove('valid');
                }
            });
            
            const isValid = Object.values(requirements).every(Boolean);
            updateValidationUI(input, 'passwordIcon', isValid);
            
            // Update confirm password validation if it has a value
            const confirmPassword = document.getElementById('confirm_password');
            if (confirmPassword.value) {
                validateConfirmPassword(confirmPassword);
            }
            
            validateForm();
            return isValid;
        }

        function validateConfirmPassword(input) {
            const password = document.getElementById('password').value;
            const value = input.value;
            const isValid = value === password && value !== '';
            
            updateValidationUI(input, 'confirmPasswordIcon', isValid);
            validateForm();
            return isValid;
        }

        function updateValidationUI(input, iconId, isValid) {
            input.classList.remove('valid', 'invalid');
            const icon = document.getElementById(iconId);
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
        }

        function validateForm() {
            const name = document.getElementById('name');
            const username = document.getElementById('username');
            const email = document.getElementById('email');
            const password = document.getElementById('password');
            const confirmPassword = document.getElementById('confirm_password');
            
            const isNameValid = name.classList.contains('valid');
            const isUsernameValid = username.classList.contains('valid');
            const isEmailValid = email.classList.contains('valid');
            const isPasswordValid = password.classList.contains('valid');
            const isConfirmPasswordValid = confirmPassword.classList.contains('valid');
            
            const signupButton = document.getElementById('signupButton');
            signupButton.disabled = !(isNameValid && isUsernameValid && isEmailValid && 
                                    isPasswordValid && isConfirmPasswordValid);
        }

        // Add event listeners for input validation
        document.addEventListener('DOMContentLoaded', function() {
            const inputs = ['name', 'username', 'email', 'password', 'confirm_password'];
            inputs.forEach(id => {
                const input = document.getElementById(id);
                if (input.value) {
                    switch(id) {
                        case 'name':
                            validateName(input);
                            break;
                        case 'username':
                            validateUsername(input);
                            break;
                        case 'email':
                            validateEmail(input);
                            break;
                        case 'password':
                            validatePassword(input);
                            break;
                        case 'confirm_password':
                            validateConfirmPassword(input);
                            break;
                    }
                }
            });
        });

        if (DEBUG) {
            logDebug('Page loaded');
            logDebug('Selected role:', '<?php echo $selected_role; ?>');
        }
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 