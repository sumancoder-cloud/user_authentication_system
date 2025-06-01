<?php
require_once 'config.php';
require_once 'security.php';

// Apply security measures
securePage();

// Validate page access
validatePageAccess();

// Get user information
$user_id = $_SESSION['user_id'];
$sql = "SELECT name, username, email, created_at FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);

// Get display name (prefer username, fallback to name, then email)
$display_name = $user['username'] ?? $user['name'] ?? $user['email'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Addwise</title>
    <!-- Add meta tags to prevent caching -->
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <!-- Add additional security meta tags -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="robots" content="noindex, nofollow">
    <link rel="stylesheet" href="form.css">
    <script>
        // Handle navigation and session
        (function() {
            // Store the current page token and URL
            const pageToken = '<?php echo $_SESSION['page_token']; ?>';
            const currentUrl = window.location.href;
            
            // Function to validate session
            async function validateSession() {
                try {
                    const response = await fetch('validate_session.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            token: pageToken
                        })
                    });
                    const data = await response.json();
                    if (!data.valid) {
                        window.location.replace('logout.php');
                    }
                } catch (error) {
                    console.error('Session validation failed:', error);
                }
            }

            // Function to hide back button
            function hideBackButton() {
                // Replace the current history entry
                window.history.replaceState(null, '', currentUrl);
                
                // Clear all previous history entries
                window.history.pushState(null, '', currentUrl);
                
                // Prevent any new history entries
                window.addEventListener('popstate', function(event) {
                    window.history.pushState(null, '', currentUrl);
                });

                // Disable backspace key navigation
                document.addEventListener('keydown', function(e) {
                    if (e.key === 'Backspace' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
                        e.preventDefault();
                    }
                });

                // Override history methods to prevent back button
                const originalPushState = window.history.pushState;
                window.history.pushState = function() {
                    originalPushState.apply(this, arguments);
                    // Clear any previous history
                    window.history.replaceState(null, '', currentUrl);
                };
            }

            // Initialize everything when the page loads
            document.addEventListener('DOMContentLoaded', function() {
                // Hide back button immediately
                hideBackButton();
                
                // Start periodic session validation
                setInterval(validateSession, 3000);

                // Add welcome animation
                const welcomeContainer = document.querySelector('.welcome-container');
                if (welcomeContainer) {
                    welcomeContainer.style.opacity = '0';
                    welcomeContainer.style.transform = 'translateY(20px)';
                    welcomeContainer.style.transition = 'all 0.5s ease-out';
                    
                    setTimeout(() => {
                        welcomeContainer.style.opacity = '1';
                        welcomeContainer.style.transform = 'translateY(0)';
                    }, 100);
                }
            });

            // Also hide back button when page is shown
            window.addEventListener('pageshow', function(event) {
                if (event.persisted) {
                    hideBackButton();
                }
            });
        })();
    </script>
    <style>
        .welcome-container {
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 600px;
            text-align: center;
            margin: 50px auto;
        }

        .welcome-title {
            color: #ffcc00;
            font-size: 2.5em;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .welcome-message {
            color: #fff;
            font-size: 1.2em;
            margin-bottom: 30px;
            line-height: 1.6;
        }

        .user-name {
            color: #ffcc00;
            font-weight: bold;
            font-size: 1.4em;
            margin: 20px 0;
            padding: 10px;
            border: 2px solid #ffcc00;
            border-radius: 8px;
            display: inline-block;
        }

        .action-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 30px;
        }

        .action-button {
            padding: 12px 30px;
            background: #ffcc00;
            color: black;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 16px;
        }

        .action-button:hover {
            background: #fff;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }

        .logout-button {
            background: #dc3545;
            color: white;
        }

        .logout-button:hover {
            background: #c82333;
        }

        .welcome-icon {
            font-size: 4em;
            color: #ffcc00;
            margin-bottom: 20px;
        }

        .quick-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin: 30px 0;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
        }

        .stat-item {
            padding: 15px;
            background: rgba(255, 204, 0, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(255, 204, 0, 0.2);
        }

        .stat-label {
            color: #ffcc00;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .stat-value {
            color: #fff;
            font-size: 1.4em;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="welcome-container">
        <div class="welcome-icon">👋</div>
        <h1 class="welcome-title">Welcome to Addwise</h1>
        <div class="welcome-message">
            We're excited to have you here!
        </div>
        <div class="user-name">
            <?php echo htmlspecialchars($display_name); ?>
        </div>

        <div class="quick-stats">
            <div class="stat-item">
                <div class="stat-label">Member Since</div>
                <div class="stat-value"><?php echo date('M Y', strtotime($user['created_at'] ?? 'now')); ?></div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Account Status</div>
                <div class="stat-value">Active</div>
            </div>
        </div>

        <div class="action-buttons">
            <a href="dashboard.php" class="action-button">Go to Dashboard</a>
            <a href="logout.php" class="action-button logout-button">Logout</a>
        </div>
    </div>
</body>
</html><?php mysqli_close($conn); ?> 