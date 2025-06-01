<?php
require_once 'config.php';
require_once 'auth.php';

// Initialize Auth class
$auth = new Auth($conn);

// Perform logout
$auth->logout();

// If for some reason the redirect in Auth class didn't work, force redirect here
header("Location: login.php");
exit();
?> 