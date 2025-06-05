<?php
require_once 'config.php';
require_once 'auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if role is selected
if (!isset($_SESSION['selected_role'])) {
    header("Location: select_role.php");
    exit();
}

$selected_role = $_SESSION['selected_role'];
$name = $username = $email = $password = "";
$name_err = $username_err = $email_err = $password_err = $signup_err = "";

// Initialize Auth class
$auth = new Auth($conn);

// Process Google signup form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['google_signup'])) {
        // Validate name
        if (empty(trim($_POST["name"] ?? ''))) {
            $name_err = "Please enter your name.";
        } else {
            $name = trim($_POST["name"]);
        }

        // Validate username
        if (empty(trim($_POST["username"] ?? ''))) {
            $username_err = "Please enter a username.";
        } else {
            $username = trim($_POST["username"]);
        }

        // Validate email
        if (empty(trim($_POST["email"] ?? ''))) {
            $email_err = "Please enter your email.";
        } else {
            $email = trim($_POST["email"]);
        }

        // Validate password (Google account password)
        if (empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter your Google account password.";
        } else {
            $password = trim($_POST["password"]);
        }

        // If no validation errors, proceed with Google signup
        if (empty($name_err) && empty($username_err) && empty($email_err) && empty($password_err)) {
            // Attempt to register as Google account
            $result = $auth->register($name, $username, $email, $password, $selected_role, true);
            
            if ($result['success']) {
                // Store success message
                $_SESSION['success_message'] = 'Google account registration successful. Please login.';
                
                // Redirect to login page
                header("Location: login.php");
                exit();
            } else {
                $signup_err = $result['message'];
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Google Signup - Addwise</title>
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
        
        button[type="submit"] {
            width: 100%;
            padding: 12px;
            background: #4285f4;
            color: white;
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
            background: #357abd;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
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
    </style>
</head>
<body>
    <div class="form-container">
        <form id="googleSignupForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <h2>Create <?php echo ucfirst($selected_role); ?> Account with Google</h2>
            
            <div class="role-badge <?php echo $selected_role; ?>">
                <?php echo ucfirst($selected_role); ?> Account
            </div>
            
            <div class="error-message" style="display: <?php echo !empty($signup_err) ? 'block' : 'none'; ?>">
                <?php echo $signup_err; ?>
            </div>

            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" required 
                       value="<?php echo htmlspecialchars($name); ?>">
            </div>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       value="<?php echo htmlspecialchars($username); ?>">
            </div>

            <div class="form-group">
                <label for="email">Google Email</label>
                <input type="email" id="email" name="email" required 
                       value="<?php echo htmlspecialchars($email); ?>">
            </div>

            <div class="form-group">
                <label for="password">Google Account Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit" name="google_signup">Sign up with Google</button>

            <p class="switch">Already have an account? <a href="login.php">Login</a></p>
            <a href="select_role.php" class="change-role">Change Role</a>
        </form>
    </div>
</body>
</html>
<?php
mysqli_close($conn);
?>