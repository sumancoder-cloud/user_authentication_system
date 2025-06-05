<?php
require_once 'config.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Function to execute SQL queries safely
function executeQuery($conn, $sql) {
    if (mysqli_query($conn, $sql)) {
        echo "Query executed successfully: " . $sql . "<br>";
        return true;
    } else {
        echo "Error executing query: " . mysqli_error($conn) . "<br>";
        return false;
    }
}

// Add new columns to users table
$alter_queries = [
    // Add status column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS status ENUM('active', 'inactive', 'suspended') DEFAULT 'active'",
    
    // Add email_verified column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE",
    
    // Add verification_token column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255) DEFAULT NULL",
    
    // Add last_login column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login DATETIME DEFAULT NULL",
    
    // Add login_attempts column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INT DEFAULT 0",
    
    // Add created_at column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
    
    // Add updated_at column if not exists
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
];

// Execute each alter query
foreach ($alter_queries as $sql) {
    executeQuery($conn, $sql);
}

// Create login_attempts table if not exists
$create_login_attempts_table = "
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time DATETIME NOT NULL,
    success BOOLEAN DEFAULT FALSE,
    INDEX (email),
    INDEX (attempt_time)
)";

executeQuery($conn, $create_login_attempts_table);

// Create otp_verification table if not exists
$create_otp_table = "
CREATE TABLE IF NOT EXISTS otp_verification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    purpose ENUM('registration', 'login', 'password_reset') NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    INDEX (email),
    INDEX (created_at)
)";

executeQuery($conn, $create_otp_table);

// Update existing users to have verified email
$update_existing_users = "
UPDATE users 
SET email_verified = TRUE, 
    status = 'active' 
WHERE email_verified IS NULL 
   OR email_verified = FALSE";

executeQuery($conn, $update_existing_users);

echo "<br>Database update completed successfully!";

// Close the connection
mysqli_close($conn);
?> 