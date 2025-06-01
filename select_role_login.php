<?php
require_once 'config.php';

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Clear any existing role selection
unset($_SESSION['selected_role']);

$error = isset($_SESSION['error']) ? $_SESSION['error'] : '';
unset($_SESSION['error']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Select Role for Login - Addwise</title>
    <link rel="stylesheet" href="form.css">
    <style>
        .role-container {
            display: flex;
            gap: 20px;
            margin: 30px 0;
        }
        
        .role-card {
            flex: 1;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            border: 2px solid transparent;
            position: relative;
        }
        
        .role-card:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.1);
        }
        
        .role-card.selected {
            border-color: #ffcc00;
            background: rgba(255, 204, 0, 0.1);
        }
        
        .role-icon {
            font-size: 48px;
            margin-bottom: 15px;
            color: #ffcc00;
        }
        
        .role-title {
            font-size: 24px;
            margin-bottom: 10px;
            color: #fff;
        }
        
        .role-description {
            color: #ccc;
            margin-bottom: 20px;
            font-size: 14px;
            line-height: 1.5;
        }
        
        .error-message {
            background: rgba(220, 53, 69, 0.1);
            color: #dc3545;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .continue-button {
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
            opacity: 0.5;
            pointer-events: none;
        }
        
        .continue-button.active {
            opacity: 1;
            pointer-events: auto;
        }
        
        .continue-button:hover {
            background: #fff;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        .form-container {
            max-width: 800px;
        }
        
        .role-card input[type="radio"] {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            margin: 0;
            cursor: pointer;
        }
        
        .role-card label {
            display: block;
            cursor: pointer;
            height: 100%;
            width: 100%;
        }
        
        .switch {
            text-align: center;
            margin-top: 20px;
            color: #fff;
        }
        
        .switch a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
        }
        
        .switch a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="roleForm" action="process_role_login.php" method="post" onsubmit="return validateForm()">
            <h2>Select Your Role to Login</h2>
            
            <?php if (!empty($error)): ?>
                <div class="error-message">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <div class="role-container">
                <div class="role-card">
                    <input type="radio" name="role" id="role_user" value="user" required>
                    <label for="role_user">
                        <div class="role-icon">👤</div>
                        <div class="role-title">User</div>
                        <div class="role-description">
                            Login as a regular user to access your account and services.
                        </div>
                    </label>
                </div>
                
                <div class="role-card">
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
            
            <button type="submit" id="continueButton" class="continue-button">Continue to Login</button>
            
            <p class="switch">Don't have an account? <a href="select_role.php">Sign Up</a></p>
        </form>
    </div>

    <script>
        // Function to validate form before submission
        function validateForm() {
            const selectedRole = document.querySelector('input[name="role"]:checked');
            if (!selectedRole) {
                alert('Please select a role to continue');
                return false;
            }
            return true;
        }

        // Add click handlers for role cards
        document.querySelectorAll('.role-card').forEach(card => {
            card.addEventListener('click', function() {
                const radio = this.querySelector('input[type="radio"]');
                radio.checked = true;
                
                // Remove selected class from all cards
                document.querySelectorAll('.role-card').forEach(c => {
                    c.classList.remove('selected');
                });
                
                // Add selected class to clicked card
                this.classList.add('selected');
                
                // Enable continue button
                document.getElementById('continueButton').classList.add('active');
            });
        });

        // Add change handlers for radio buttons
        document.querySelectorAll('input[name="role"]').forEach(radio => {
            radio.addEventListener('change', function() {
                if (this.checked) {
                    // Remove selected class from all cards
                    document.querySelectorAll('.role-card').forEach(card => {
                        card.classList.remove('selected');
                    });
                    
                    // Add selected class to parent card
                    this.closest('.role-card').classList.add('selected');
                    
                    // Enable continue button
                    document.getElementById('continueButton').classList.add('active');
                }
            });
        });

        // Debug logging
        const DEBUG = true;
        function logDebug(...args) {
            if (DEBUG) {
                console.log('[DEBUG]', ...args);
            }
        }

        // Log initial state
        if (DEBUG) {
            logDebug('Page loaded');
            logDebug('Form elements:', {
                form: document.getElementById('roleForm'),
                continueButton: document.getElementById('continueButton'),
                roleInputs: document.querySelectorAll('input[name="role"]')
            });
        }
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 