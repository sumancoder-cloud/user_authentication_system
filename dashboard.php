<?php
require_once 'config.php';
require_once 'security.php';

// Apply security measures
securePage();

// Get user information
$user_id = $_SESSION['user_id'];
$sql = "SELECT name, username, email, role FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);

// ... rest of your existing dashboard.php code ...
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Addwise</title>
    <!-- Add meta tags to prevent caching -->
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <!-- Rest of your head content -->
</head>
<body>
    <!-- Rest of your existing dashboard.php code -->
</body>
</html> 