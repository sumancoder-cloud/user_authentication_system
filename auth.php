<?php
require_once 'config.php';
require_once 'email_handler.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Auth {
    private $conn;
    private $session_lifetime = 3600; // 1 hour
    private $max_login_attempts = 5;
    private $lockout_time = 900; // 15 minutes
    private $emailHandler;

    public function __construct($conn) {
        $this->conn = $conn;
        $this->emailHandler = new EmailHandler();
        $this->startSecureSession();

        // Create email_verification table if it doesn't exist
        $sql = "CREATE TABLE IF NOT EXISTS email_verification (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            verified_at DATETIME DEFAULT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX (token),
            INDEX (created_at)
        )";

        if (!mysqli_query($conn, $sql)) {
            error_log("Error creating email_verification table: " . mysqli_error($conn));
        }
    }

    private function startSecureSession() {
        if (session_status() === PHP_SESSION_NONE) {
            // Set secure session parameters
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1);
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.gc_maxlifetime', $this->session_lifetime);
            
            session_start();
        }
    }

    public function register($name, $username, $email, $password, $role = 'user', $is_google = false) {
        try {
            // For Google sign-in, always use email as username
            if ($is_google) {
                $username = $email;
            }

            // Validate input with is_google parameter
            if (!$this->validateRegistrationInput($name, $username, $email, $password, $is_google)) {
                return ['success' => false, 'message' => 'Invalid input data'];
            }

            // Validate role
            if (!in_array($role, ['user', 'admin'])) {
                return ['success' => false, 'message' => 'Invalid role selected'];
            }

            // Additional validation for admin registration
            if ($role === 'admin') {
                if ($email === 'sumanyadav_tati@srmap.edu.in') {
                    // Allow this specific email
                } else if (!preg_match('/@srmap\.edu\.in$/', $email)) {
                    return ['success' => false, 'message' => 'Admin accounts must use an authorized email domain'];
                }
            }

            // Check if email already exists
            if ($this->emailExists($email)) {
                return ['success' => false, 'message' => 'Email already registered'];
            }

            // Check if username already exists
            if ($this->usernameExists($username)) {
                return ['success' => false, 'message' => 'Username already taken'];
            }

            // Hash password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // For Google sign-in, auto-verify email
            if ($is_google) {
                $sql = "INSERT INTO users (name, username, email, password, role, email_verified, status, created_at) 
                        VALUES (?, ?, ?, ?, ?, 1, 'active', NOW())";
            } else {
                $sql = "INSERT INTO users (name, username, email, password, role, email_verified, created_at) 
                        VALUES (?, ?, ?, ?, ?, 0, NOW())";
            }
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "sssss", $name, $username, $email, $hashed_password, $role);
            
            if (mysqli_stmt_execute($stmt)) {
                $user_id = mysqli_insert_id($this->conn);
                
                if ($is_google) {
                    // For Google sign-in, no need for OTP
                    return [
                        'success' => true,
                        'message' => 'Registration successful',
                        'user_id' => $user_id
                    ];
                } else {
                    // Generate and send OTP
                    $otp_result = $this->generateAndSendOTP($email, 'registration');
                    
                    if ($otp_result['success']) {
                        // Store temporary auth data in session
                        $_SESSION['temp_auth'] = [
                            'user_id' => $user_id,
                            'email' => $email,
                            'purpose' => 'registration'
                        ];
                        
                        return [
                            'success' => true,
                            'message' => 'Registration successful. Please enter the OTP sent to your email.',
                            'user_id' => $user_id
                        ];
                    } else {
                        // If OTP sending fails, delete the user
                        $delete_sql = "DELETE FROM users WHERE id = ?";
                        $delete_stmt = mysqli_prepare($this->conn, $delete_sql);
                        mysqli_stmt_bind_param($delete_stmt, "i", $user_id);
                        mysqli_stmt_execute($delete_stmt);
                        
                        return [
                            'success' => false,
                            'message' => 'Failed to send verification code. Please try again.'
                        ];
                    }
                }
            } else {
                return ['success' => false, 'message' => 'Registration failed. Please try again.'];
            }
        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'An error occurred during registration.'];
        }
    }

    public function login($email, $password) {
        try {
            // Check if account is locked
            if ($this->isAccountLocked($email)) {
                return [
                    'success' => false,
                    'message' => 'Account is temporarily locked. Please try again later.'
                ];
            }

            // Get user from database
            $sql = "SELECT id, name, email, password, role, status, email_verified 
                    FROM users WHERE email = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($user = mysqli_fetch_assoc($result)) {
                // Verify password
                if (password_verify($password, $user['password'])) {
                    // Check if email is verified
                    if (!$user['email_verified']) {
                        return [
                            'success' => false,
                            'message' => 'Please verify your email before logging in.'
                        ];
                    }

                    // Check account status
                    if ($user['status'] !== 'active') {
                        return [
                            'success' => false,
                            'message' => 'Your account is not active. Please contact support.'
                        ];
                    }

                    // Reset login attempts
                    $this->resetLoginAttempts($user['id']);

                    // Update last login
                    $this->updateLastLogin($user['id']);

                    // Set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_role'] = $user['role'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['page_token'] = bin2hex(random_bytes(32));

                    return [
                        'success' => true,
                        'message' => 'Login successful',
                        'user' => [
                            'id' => $user['id'],
                            'name' => $user['name'],
                            'email' => $user['email'],
                            'role' => $user['role']
                        ]
                    ];
                } else {
                    // Log failed attempt
                    $this->logFailedAttempt($email);
                    $this->incrementLoginAttempts($user['id']);
                    
                    return [
                        'success' => false,
                        'message' => 'Invalid email or password'
                    ];
                }
            } else {
                return [
                    'success' => false,
                    'message' => 'Invalid email or password'
                ];
            }
        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'An error occurred during login'
            ];
        }
    }

    public function googleLogin($googleUser) {
        try {
            // Check if user exists
            $sql = "SELECT id, name, email, role, status, email_verified 
                    FROM users WHERE email = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $googleUser['email']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($user = mysqli_fetch_assoc($result)) {
                // Check account status
                if ($user['status'] !== 'active') {
                    return [
                        'success' => false,
                        'message' => 'Your account is not active. Please contact support.'
                    ];
                }

                // Update last login
                $this->updateLastLogin($user['id']);

                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_role'] = $user['role'];
                $_SESSION['logged_in'] = true;
                $_SESSION['page_token'] = bin2hex(random_bytes(32));

                return [
                    'success' => true,
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['name'],
                        'email' => $user['email'],
                        'role' => $user['role']
                    ]
                ];
            } else {
                // Register new user
                $name = $googleUser['name'];
                $email = $googleUser['email'];
                $username = explode('@', $email)[0] . rand(100, 999);
                $password = bin2hex(random_bytes(16)); // Random password for Google users
                
                // Register with Google sign-in
                $result = $this->register($name, $username, $email, $password, 'user', true);
                
                if ($result['success']) {
                    // Auto-verify email for Google users
                    $this->verifyEmail($email);
                    
                    // Set session variables
                    $_SESSION['user_id'] = $result['user_id'];
                    $_SESSION['user_role'] = 'user';
                    $_SESSION['logged_in'] = true;
                    $_SESSION['page_token'] = bin2hex(random_bytes(32));

                    return [
                        'success' => true,
                        'message' => 'Registration and login successful',
                        'user' => [
                            'id' => $result['user_id'],
                            'name' => $name,
                            'email' => $email,
                            'role' => 'user'
                        ]
                    ];
                } else {
                    return $result;
                }
            }
        } catch (Exception $e) {
            error_log("Google login error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'An error occurred during Google login'
            ];
        }
    }

    private function validateRegistrationInput($name, $username, $email, $password, $is_google = false) {
        // Validate name
        if (empty($name) || strlen($name) < 2 || !preg_match('/^[a-zA-Z ]*$/', $name)) {
            return false;
        }

        // For Google sign-in, username must be email
        if ($is_google) {
            if ($username !== $email) {
                return false;
            }
        } else {
            // Regular username validation
            if (empty($username) || strlen($username) < 3 || !preg_match('/^[a-zA-Z0-9_]*$/', $username)) {
                return false;
            }
        }

        // Validate email
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        // For Google sign-in, skip password validation
        if (!$is_google) {
            // Validate password
            if (empty($password) || strlen($password) < 8 || 
                !preg_match('/[A-Z]/', $password) || 
                !preg_match('/[a-z]/', $password) || 
                !preg_match('/[0-9]/', $password) || 
                !preg_match('/[^A-Za-z0-9]/', $password)) {
                return false;
            }
        }

        return true;
    }

    private function emailExists($email) {
        $sql = "SELECT id FROM users WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        return mysqli_stmt_num_rows($stmt) > 0;
    }

    private function usernameExists($username) {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        return mysqli_stmt_num_rows($stmt) > 0;
    }

    private function verifyEmail($email) {
        $sql = "UPDATE users SET email_verified = 1, status = 'active' WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        return mysqli_stmt_execute($stmt);
    }

    private function updateLastLogin($user_id) {
        $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
    }

    private function isAccountLocked($email) {
        $sql = "SELECT COUNT(*) as attempts FROM login_attempts 
                WHERE email = ? AND success = FALSE 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "si", $email, $this->lockout_time);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);
        
        return $row['attempts'] >= $this->max_login_attempts;
    }

    private function logFailedAttempt($email) {
        $sql = "INSERT INTO login_attempts (email, ip_address, attempt_time) 
                VALUES (?, ?, NOW())";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        $ip = $_SERVER['REMOTE_ADDR'];
        mysqli_stmt_bind_param($stmt, "ss", $email, $ip);
        mysqli_stmt_execute($stmt);
    }

    private function incrementLoginAttempts($user_id) {
        $sql = "UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
    }

    private function resetLoginAttempts($user_id) {
        $sql = "UPDATE users SET login_attempts = 0 WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
    }

    public function logout() {
        // Unset all session variables
        $_SESSION = array();

        // Destroy the session
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }

        // Redirect to login page
        header("Location: login.php");
        exit();
    }

    public function generateAndSendOTP($email, $purpose) {
        try {
            // Generate 6-digit OTP
            $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            
            // First, delete any existing OTP for this email and purpose
            $delete_sql = "DELETE FROM otp_verification WHERE email = ? AND purpose = ?";
            $delete_stmt = mysqli_prepare($this->conn, $delete_sql);
            mysqli_stmt_bind_param($delete_stmt, "ss", $email, $purpose);
            mysqli_stmt_execute($delete_stmt);
            
            // Now insert the new OTP
            $sql = "INSERT INTO otp_verification (email, otp, purpose, created_at, expires_at) 
                    VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 10 MINUTE))";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "sss", $email, $otp, $purpose);
            
            if (mysqli_stmt_execute($stmt)) {
                // Send OTP via email
                if ($this->emailHandler->sendOTPEmail($email, $otp)) {
                    return [
                        'success' => true,
                        'message' => 'OTP sent successfully'
                    ];
                }
            }
            
            return [
                'success' => false,
                'message' => 'Failed to send OTP'
            ];
        } catch (Exception $e) {
            error_log("OTP generation error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'An error occurred while generating OTP'
            ];
        }
    }

    public function verifyOTP($email, $otp, $purpose) {
        try {
            // Get the most recent OTP for this email and purpose
            $sql = "SELECT otp, created_at, is_used 
                    FROM otp_verification 
                    WHERE email = ? AND purpose = ? 
                    AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                    AND is_used = FALSE 
                    ORDER BY created_at DESC LIMIT 1";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $email, $purpose);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($row = mysqli_fetch_assoc($result)) {
                // Verify OTP
                if ($row['otp'] === $otp) {
                    // Mark OTP as used
                    $update_sql = "UPDATE otp_verification SET is_used = TRUE WHERE email = ? AND otp = ? AND purpose = ?";
                    $update_stmt = mysqli_prepare($this->conn, $update_sql);
                    mysqli_stmt_bind_param($update_stmt, "sss", $email, $otp, $purpose);
                    mysqli_stmt_execute($update_stmt);
                    
                    // Handle different purposes
                    switch ($purpose) {
                        case 'registration':
                            // Verify email and activate user
                            $update_user = "UPDATE users SET email_verified = 1, status = 'active' WHERE email = ?";
                            $update_stmt = mysqli_prepare($this->conn, $update_user);
                            mysqli_stmt_bind_param($update_stmt, "s", $email);
                            mysqli_stmt_execute($update_stmt);
                            
                            // Clear temporary auth data
                            unset($_SESSION['temp_auth']);
                            
                            return [
                                'success' => true,
                                'message' => 'Email verified successfully. You can now login.'
                            ];
                            
                        case 'login':
                            return [
                                'success' => true,
                                'message' => 'Login verified successfully'
                            ];
                            
                        case 'password_reset':
                            // Generate password reset token
                            $token = bin2hex(random_bytes(32));
                            $update_sql = "UPDATE users SET 
                                         password_reset_token = ?, 
                                         password_reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) 
                                         WHERE email = ?";
                            $update_stmt = mysqli_prepare($this->conn, $update_sql);
                            mysqli_stmt_bind_param($update_stmt, "ss", $token, $email);
                            mysqli_stmt_execute($update_stmt);
                            
                            return [
                                'success' => true,
                                'message' => 'Password reset verified',
                                'token' => $token
                            ];
                            
                        default:
                            return [
                                'success' => false,
                                'message' => 'Invalid verification purpose'
                            ];
                    }
                }
            }
            
            return [
                'success' => false,
                'message' => 'Invalid or expired verification code'
            ];
        } catch (Exception $e) {
            error_log("OTP verification error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'An error occurred during verification'
            ];
        }
    }

    public function verifyEmailToken($token) {
        try {
            // First check if token exists and is not expired
            $sql = "SELECT user_id, created_at FROM email_verification 
                   WHERE token = ? AND is_verified = 0 
                   AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
            
            if ($stmt = mysqli_prepare($this->conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $token);
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);
                
                if ($row = mysqli_fetch_assoc($result)) {
                    // Token is valid, update user and verification status
                    mysqli_begin_transaction($this->conn);
                    
                    try {
                        // Update user's email_verified status
                        $update_user = "UPDATE users SET email_verified = 1 
                                      WHERE id = ?";
                        $stmt = mysqli_prepare($this->conn, $update_user);
                        mysqli_stmt_bind_param($stmt, "i", $row['user_id']);
                        mysqli_stmt_execute($stmt);
                        
                        // Mark token as verified
                        $update_token = "UPDATE email_verification 
                                       SET is_verified = 1, verified_at = NOW() 
                                       WHERE token = ?";
                        $stmt = mysqli_prepare($this->conn, $update_token);
                        mysqli_stmt_bind_param($stmt, "s", $token);
                        mysqli_stmt_execute($stmt);
                        
                        mysqli_commit($this->conn);
                        return ['success' => true, 'message' => 'Email verified successfully'];
                    } catch (Exception $e) {
                        mysqli_rollback($this->conn);
                        error_log("Error verifying email: " . $e->getMessage());
                        return ['success' => false, 'message' => 'Error verifying email. Please try again.'];
                    }
                } else {
                    return ['success' => false, 'message' => 'Invalid or expired verification link.'];
                }
            }
            
            return ['success' => false, 'message' => 'Error processing verification.'];
        } catch (Exception $e) {
            error_log("Error in verifyEmailToken: " . $e->getMessage());
            return ['success' => false, 'message' => 'An error occurred. Please try again.'];
        }
    }

    public function getUserByEmail($email) {
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
}
?> 