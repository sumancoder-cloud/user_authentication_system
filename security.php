<?php
// Remove the session_start() from here since it's handled in initSecureSession
// session_start(); // Remove this line

function checkAuth() {
    // Check if user is logged in
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        // Redirect to login if not authenticated
        header("Location: login.php");
        exit();
    }
}

function preventBackButton() {
    // Prevent caching of pages
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // Date in the past
    
    // Enhanced JavaScript to prevent back/forward navigation
    echo '<script type="text/javascript">
        // Immediately clear any existing history
        window.history.pushState(null, "", window.location.href);
        
        // Function to force reload and clear sensitive data
        function forceReload() {
            // Clear any sensitive form data
            document.querySelectorAll("input[type=password]").forEach(function(input) {
                input.value = "";
            });
            
            // Force reload the page
            window.location.href = window.location.href;
        }

        // Function to prevent navigation
        function preventNavigation(e) {
            if (e) {
                e.preventDefault();
                e.stopPropagation();
            }
            // Force reload the page
            forceReload();
            return false;
        }

        // Clear history and prevent back button
        window.onpopstate = function(e) {
            preventNavigation(e);
        };

        // Prevent forward button and cached pages
        window.addEventListener("pageshow", function(e) {
            if (e.persisted) {
                preventNavigation(e);
            }
        });

        // Disable all navigation keys
        document.addEventListener("keydown", function(e) {
            // Prevent backspace navigation
            if (e.keyCode === 8 && !e.target.matches("input, textarea")) {
                e.preventDefault();
            }
            // Prevent Alt+Left/Right (back/forward)
            if (e.altKey && (e.keyCode === 37 || e.keyCode === 39)) {
                e.preventDefault();
            }
            // Prevent Ctrl+R (refresh)
            if (e.ctrlKey && e.keyCode === 82) {
                e.preventDefault();
            }
            // Prevent F5
            if (e.keyCode === 116) {
                e.preventDefault();
            }
        });

        // Clear history on page load
        window.onload = function() {
            // Clear the history stack
            window.history.pushState(null, "", window.location.href);
            window.history.pushState(null, "", window.location.href);
            window.history.pushState(null, "", window.location.href);
            
            // Replace the current history entry
            window.history.replaceState(null, "", window.location.href);
            
            // Clear any sensitive data from forms
            document.querySelectorAll("form").forEach(function(form) {
                form.reset();
            });
        };

        // Prevent leaving the page
        window.addEventListener("beforeunload", function(e) {
            // Clear sensitive data
            document.querySelectorAll("input[type=password]").forEach(function(input) {
                input.value = "";
            });
            
            // Show confirmation dialog
            e.preventDefault();
            e.returnValue = "Are you sure you want to leave? Your session will be cleared for security reasons.";
            return e.returnValue;
        });

        // Continuous protection
        setInterval(function() {
            // Keep pushing to history
            window.history.pushState(null, "", window.location.href);
            
            // Clear any sensitive data that might have been restored
            document.querySelectorAll("input[type=password]").forEach(function(input) {
                if (input.value) {
                    input.value = "";
                }
            });
        }, 50);

        // Disable right-click and context menu
        document.addEventListener("contextmenu", function(e) {
            e.preventDefault();
            return false;
        });

        // Disable text selection
        document.addEventListener("selectstart", function(e) {
            e.preventDefault();
            return false;
        });

        // Disable drag and drop
        document.addEventListener("dragstart", function(e) {
            e.preventDefault();
            return false;
        });

        // Clear any existing history entries
        if (window.history && window.history.pushState) {
            // Clear the history stack
            for (let i = 0; i < 10; i++) {
                window.history.pushState(null, "", window.location.href);
            }
            
            // Replace the current history entry
            window.history.replaceState(null, "", window.location.href);
            
            // Listen for any navigation attempts
            window.addEventListener("popstate", function() {
                preventNavigation();
            });
        }

        // Additional protection against browser back/forward
        window.addEventListener("unload", function() {
            // Clear any sensitive data
            document.querySelectorAll("input[type=password]").forEach(function(input) {
                input.value = "";
            });
        });

        // Disable browser back/forward buttons
        document.addEventListener("keyup", function(e) {
            if (e.keyCode === 8 || (e.altKey && (e.keyCode === 37 || e.keyCode === 39))) {
                e.preventDefault();
                forceReload();
            }
        });
    </script>';
}

function secureHeaders() {
    // Set security headers
    header("X-Frame-Options: DENY"); // Prevent clickjacking
    header("X-XSS-Protection: 1; mode=block"); // Enable XSS protection
    header("X-Content-Type-Options: nosniff"); // Prevent MIME type sniffing
    header("Referrer-Policy: strict-origin-when-cross-origin"); // Control referrer information
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"); // CSP
}

function initSecureSession() {
    // Only start session if not already started
    if (session_status() === PHP_SESSION_NONE) {
        // Set secure session parameters
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1);
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_lifetime', 0); // Session cookie expires when browser closes
        
        session_start();
    }
    
    // Regenerate session ID periodically
    if (!isset($_SESSION['last_regeneration']) || 
        time() - $_SESSION['last_regeneration'] > 300) { // Every 5 minutes
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

// Function to include at the start of every protected page
function securePage() {
    // Start session if not already started
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Check if user is logged in
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        // Clear any existing session
        session_unset();
        session_destroy();
        header("Location: login.php");
        exit();
    }

    // Generate a new session token if it doesn't exist
    if (!isset($_SESSION['page_token'])) {
        $_SESSION['page_token'] = bin2hex(random_bytes(32));
    }

    // Store the current page token in session
    $_SESSION['last_page'] = $_SERVER['REQUEST_URI'];
    $_SESSION['last_token'] = $_SESSION['page_token'];

    // Set security headers
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
}

// Function to validate page access
function validatePageAccess() {
    if (!isset($_SESSION['page_token']) || !isset($_SESSION['last_token'])) {
        header("Location: login.php");
        exit();
    }

    // Check if the tokens match
    if ($_SESSION['page_token'] !== $_SESSION['last_token']) {
        // If tokens don't match, redirect to the last valid page
        if (isset($_SESSION['last_page'])) {
            header("Location: " . $_SESSION['last_page']);
            exit();
        } else {
            header("Location: welcome.php");
            exit();
        }
    }

    // Generate new token for next page
    $_SESSION['page_token'] = bin2hex(random_bytes(32));
}
?> 
?> 