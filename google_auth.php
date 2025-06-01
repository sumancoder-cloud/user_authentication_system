<?php
require_once 'config.php';
require_once 'auth.php';

class GoogleAuth {
    private $client_id;
    private $client_secret;
    private $redirect_uri;
    private $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth';
    private $token_url = 'https://oauth2.googleapis.com/token';
    private $userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo';

    public function __construct() {
        $this->client_id = GOOGLE_CLIENT_ID;
        $this->client_secret = GOOGLE_CLIENT_SECRET;
        $this->redirect_uri = GOOGLE_REDIRECT_URI;
    }

    public function getAuthUrl() {
        $params = [
            'client_id' => $this->client_id,
            'redirect_uri' => $this->redirect_uri,
            'response_type' => 'code',
            'scope' => 'email profile',
            'access_type' => 'online',
            'prompt' => 'select_account'
        ];
        
        return $this->auth_url . '?' . http_build_query($params);
    }

    public function getAccessToken($code) {
        error_log("=== Getting Access Token ===");
        error_log("Code: " . $code);
        error_log("Client ID: " . $this->client_id);
        error_log("Redirect URI: " . $this->redirect_uri);
        
        $params = [
            'code' => $code,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->redirect_uri,
            'grant_type' => 'authorization_code'
        ];

        error_log("Token request parameters: " . print_r($params, true));

        $ch = curl_init($this->token_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        
        error_log("HTTP Response Code: " . $http_code);
        error_log("Curl Error: " . $curl_error);
        error_log("Response: " . $response);
        
        curl_close($ch);

        if ($curl_error) {
            error_log("Curl error occurred: " . $curl_error);
            throw new Exception("Failed to connect to Google: " . $curl_error);
        }

        if ($http_code !== 200) {
            error_log("HTTP error occurred: " . $http_code);
            throw new Exception("Google returned error code: " . $http_code);
        }

        $token_data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("JSON decode error: " . json_last_error_msg());
            throw new Exception("Failed to parse Google response");
        }

        if (isset($token_data['error'])) {
            error_log("Google API error: " . print_r($token_data['error'], true));
            throw new Exception("Google API error: " . $token_data['error_description'] ?? $token_data['error']);
        }

        error_log("=== Access Token Retrieved Successfully ===");
        return $token_data;
    }

    public function getUserInfo($access_token) {
        $ch = curl_init($this->userinfo_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $access_token
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response, true);
    }

    public function handleGoogleSignup($user_info, $selected_role) {
        global $conn;
        $auth = new Auth($conn);

        // First check if email already exists
        $sql = "SELECT id, email, role FROM users WHERE email = ?";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $user_info['email']);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if ($existing_user = mysqli_fetch_assoc($result)) {
            error_log("Email already registered: " . $user_info['email']);
            return [
                'success' => false,
                'message' => 'This email is already registered. Please login instead.',
                'email_exists' => true,
                'email' => $user_info['email']
            ];
        }

        // Generate a random username from email
        $username = explode('@', $user_info['email'])[0] . rand(100, 999);
        
        // Generate a random password for the account
        $password = bin2hex(random_bytes(8));

        // Register the user
        $result = $auth->register(
            $user_info['name'],
            $username,
            $user_info['email'],
            $password,
            $selected_role
        );

        if ($result['success']) {
            // Mark email as verified since it's from Google
            $sql = "UPDATE users SET email_verified = TRUE, status = 'active' WHERE email = ?";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $user_info['email']);
            mysqli_stmt_execute($stmt);

            // Store registration success in session
            $_SESSION['registration_success'] = true;
            $_SESSION['registered_email'] = $user_info['email'];
            $_SESSION['registered_name'] = $user_info['name'];

            return [
                'success' => true,
                'message' => 'Registration successful! Please login with your email.',
                'email' => $user_info['email']
            ];
        }

        return $result;
    }
}
?> 