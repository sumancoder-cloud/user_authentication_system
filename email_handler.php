<?php
require_once 'config.php';
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class EmailHandler {
    private $mailer;
    private $from_email = 'suman.tati2005@gmail.com'; // Your Gmail address
    private $from_name = 'Addwise Verification';
    
    public function __construct() {
        $this->mailer = new PHPMailer(true);
        $this->setupMailer();
    }
    
    private function setupMailer() {
        try {
        // Server settings
        $this->mailer->isSMTP();
            $this->mailer->Host = 'smtp.gmail.com';
        $this->mailer->SMTPAuth = true;
            $this->mailer->Username = 'suman.tati2005@gmail.com';
            $this->mailer->Password = 'eabf fojg ctoz tqus';
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $this->mailer->Port = 587;
            
            // Add these lines to fix SSL/TLS issues
            $this->mailer->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                )
            );
        
        // Default sender
            $this->mailer->setFrom($this->from_email, $this->from_name);
            $this->mailer->isHTML(true);
            
            // Enable error reporting
            error_log("Email handler initialized with settings: " . 
                     "Host={$this->mailer->Host}, " .
                     "Port={$this->mailer->Port}, " .
                     "Username={$this->mailer->Username}");
                     
        } catch (Exception $e) {
            error_log("Email setup error: " . $e->getMessage());
        }
    }
    
    public function sendVerificationEmail($email, $token) {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);

            // Email content
            $this->mailer->Subject = 'Verify Your Addwise Account';
            
            // Create verification link
            $verification_link = "http://" . $_SERVER['HTTP_HOST'] . 
                               "/ADDWISEcopied/verify_email.php?token=" . $token;

            // Email body
            $body = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .button {
                            display: inline-block;
                            padding: 10px 20px;
                            background-color: #4CAF50;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            margin: 20px 0;
                        }
                        .footer { font-size: 12px; color: #666; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <h2>Welcome to Addwise!</h2>
                        <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
                        <a href='{$verification_link}' class='button'>Verify Email Address</a>
                        <p>Or copy and paste this link in your browser:</p>
                        <p>{$verification_link}</p>
                        <p>This verification link will expire in 24 hours.</p>
                        <div class='footer'>
                            <p>If you didn't create an account, you can safely ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>";

            $this->mailer->Body = $body;
            $this->mailer->AltBody = "Welcome to Addwise! Please verify your email by visiting: " . $verification_link;

            // Send email
            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Verification email error: " . $e->getMessage());
            return false;
        }
    }
    
    public function sendPasswordResetEmail($email, $token) {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);

            // Email content
            $this->mailer->Subject = 'Reset Your Addwise Password';
            
            // Create reset link
            $reset_link = "http://" . $_SERVER['HTTP_HOST'] . 
                         "/ADDWISEcopied/reset_password.php?token=" . $token;

            // Email body
            $body = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .button {
                            display: inline-block;
                            padding: 10px 20px;
                            background-color: #4CAF50;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            margin: 20px 0;
                        }
                        .footer { font-size: 12px; color: #666; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <h2>Password Reset Request</h2>
                        <p>We received a request to reset your password. Click the button below to reset it:</p>
                        <a href='{$reset_link}' class='button'>Reset Password</a>
                        <p>Or copy and paste this link in your browser:</p>
                        <p>{$reset_link}</p>
                        <p>This reset link will expire in 1 hour.</p>
                        <div class='footer'>
                            <p>If you didn't request a password reset, you can safely ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>";

            $this->mailer->Body = $body;
            $this->mailer->AltBody = "Reset your password by visiting: " . $reset_link;

            // Send email
            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Password reset email error: " . $e->getMessage());
            return false;
        }
    }
    
    public function sendOTPEmail($email, $otp) {
        try {
            error_log("Attempting to send OTP email to: " . $email);
            
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);

            // Email content
            $this->mailer->Subject = 'Your Addwise Verification Code';
            
            // Email body
            $body = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .otp-code {
                            font-size: 24px;
                            font-weight: bold;
                            color: #4CAF50;
                            padding: 10px;
                            background: #f5f5f5;
                            border-radius: 5px;
                            text-align: center;
                            margin: 20px 0;
                        }
                        .footer { font-size: 12px; color: #666; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <h2>Your Verification Code</h2>
                        <p>Please use the following code to verify your account:</p>
                        <div class='otp-code'>{$otp}</div>
                        <p>This code will expire in 10 minutes.</p>
                        <div class='footer'>
                            <p>If you didn't request this code, you can safely ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>";

            $this->mailer->Body = $body;
            $this->mailer->AltBody = "Your verification code is: " . $otp;

            // Send email
            $result = $this->mailer->send();
            error_log("OTP email sent successfully to: " . $email);
            return true;
        } catch (Exception $e) {
            error_log("OTP email error for {$email}: " . $e->getMessage());
            error_log("Full error details: " . print_r($e, true));
            return false;
        }
    }
}

// Email configuration
// To use Gmail SMTP:
// 1. Enable 2-Step Verification in your Google Account
// 2. Generate an App Password: Google Account -> Security -> App Passwords
// 3. Select "Mail" and "Other (Custom name)" -> Name it "Addwise"
// 4. Copy the 16-character password and replace 'your-app-password' below
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'suman.tati2005@gmail.com');  // Your Gmail address
// TODO: Replace the password below with your new 16-character app password from Google Account
// Go to: Google Account -> Security -> App Passwords -> Select Mail -> Other (Custom name) -> Name it "Addwise"
define('SMTP_PASSWORD', 'eabf fojg ctoz tqus');  // ← Replace this with your new app password
define('SMTP_FROM_EMAIL', 'suman.tati2005@gmail.com');
define('SMTP_FROM_NAME', 'Addwise');

function generateOTP() {
    // Generate a 6-digit OTP
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function sendOTPEmail($email, $otp, $purpose) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        
        switch ($purpose) {
            case 'registration':
                $mail->Subject = 'Verify Your Email Address';
                $mail->Body = "
                    <h2>Welcome to Our Platform!</h2>
                    <p>Thank you for registering. Please use the following code to verify your email address:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                ";
                break;
                
            case 'login':
                $mail->Subject = 'Your Login Verification Code';
                $mail->Body = "
                    <h2>Login Verification</h2>
                    <p>Please use the following code to complete your login:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't attempt to login, please secure your account immediately.</p>
                ";
                break;
                
            case 'password_reset':
                $mail->Subject = 'Password Reset Verification Code';
                $mail->Body = "
                    <h2>Password Reset Request</h2>
                    <p>Please use the following code to reset your password:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                ";
                break;
        }

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

function sendPasswordResetEmail($email, $token) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Reset Your Password';
        
        $reset_link = "http://localhost/ADDWISEcopied/reset_password.php?token=" . $token;
        
        $mail->Body = "
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password. Click the link below to reset your password:</p>
            <p><a href='{$reset_link}' style='display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
            <p>Or copy and paste this link in your browser:</p>
            <p>{$reset_link}</p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        ";

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Password reset email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

function sendWelcomeEmail($email, $name) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Welcome to Our Platform!';
        
        $mail->Body = "
            <h2>Welcome, {$name}!</h2>
            <p>Thank you for joining our platform. We're excited to have you on board!</p>
            <p>Here are a few things you can do to get started:</p>
            <ul>
                <li>Complete your profile</li>
                <li>Explore our features</li>
                <li>Connect with other users</li>
            </ul>
            <p>If you have any questions, feel free to contact our support team.</p>
            <p>Best regards,<br>Your Team</p>
        ";

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Welcome email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

function storeOTP($email, $otp, $purpose = 'registration') {
    global $conn;
    
    $sql = "SELECT id FROM otp_verification WHERE email = ? AND purpose = ?";
    if ($stmt = mysqli_prepare($conn, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $email, $purpose);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if (mysqli_stmt_num_rows($stmt) > 0) {
            $sql = "UPDATE otp_verification SET otp = ?, created_at = NOW(), attempts = 0, is_used = FALSE WHERE email = ? AND purpose = ?";
        } else {
            $sql = "INSERT INTO otp_verification (email, otp, purpose, created_at) VALUES (?, ?, ?, NOW())";
        }
        mysqli_stmt_close($stmt);
        
        if ($stmt = mysqli_prepare($conn, $sql)) {
            if (mysqli_stmt_num_rows($stmt) > 0) {
                mysqli_stmt_bind_param($stmt, "sss", $otp, $email, $purpose);
            } else {
                mysqli_stmt_bind_param($stmt, "sss", $email, $otp, $purpose);
            }
            return mysqli_stmt_execute($stmt);
        }
    }
    return false;
}

// Create OTP verification table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS otp_verification (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    purpose ENUM('registration', 'login', 'password_reset') NOT NULL,
    created_at DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    attempts INT DEFAULT 0,
    INDEX (email),
    INDEX (purpose)
)";

if (!mysqli_query($conn, $sql)) {
    die("Error creating OTP table: " . mysqli_error($conn));
}
?> 