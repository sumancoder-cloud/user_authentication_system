<?php
require_once 'config.php';

// Add missing columns to users table
$sql = "ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS username VARCHAR(50) NOT NULL UNIQUE AFTER name,
        ADD COLUMN IF NOT EXISTS verification_token VARCHAR(64) NULL,
        ADD COLUMN IF NOT EXISTS status ENUM('pending', 'active', 'suspended') NOT NULL DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS reset_token VARCHAR(64) NULL,
        ADD COLUMN IF NOT EXISTS reset_token_expires DATETIME NULL,
        ADD COLUMN IF NOT EXISTS login_attempts INT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS last_login DATETIME NULL,
        ADD COLUMN IF NOT EXISTS role ENUM('user', 'admin') NOT NULL DEFAULT 'user'";

if (mysqli_query($conn, $sql)) {
    echo "Users table updated successfully\n";
} else {
    echo "Error updating users table: " . mysqli_error($conn) . "\n";
}

// Update OTP verification table to include purpose and attempts
$sql = "ALTER TABLE otp_verification 
        ADD COLUMN IF NOT EXISTS purpose VARCHAR(20) NOT NULL DEFAULT 'registration',
        ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS is_used BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS expires_at DATETIME NULL,
        ADD UNIQUE INDEX IF NOT EXISTS idx_email_purpose (email, purpose)";

if (mysqli_query($conn, $sql)) {
    echo "OTP verification table updated successfully\n";
} else {
    echo "Error updating OTP verification table: " . mysqli_error($conn) . "\n";
}

// Add index for username
$sql_index = "CREATE UNIQUE INDEX IF NOT EXISTS idx_username ON users (username)";
if (mysqli_query($conn, $sql_index)) {
    echo "Username index created successfully\n";
} else {
    echo "Error creating username index: " . mysqli_error($conn) . "\n";
}

mysqli_close($conn);
?> 