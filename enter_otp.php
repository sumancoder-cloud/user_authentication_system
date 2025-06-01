<?php
session_start();

// Check if temp_auth session is set
if (!isset($_SESSION['temp_auth']) || !isset($_SESSION['temp_auth']['email'])) {
    header('Location: signup.php');
    exit();
}
$email = $_SESSION['temp_auth']['email'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email - OTP</title>
    <link rel="stylesheet" href="form.css">
    <style>
        body { background: #1a1a2e; color: #fff; font-family: 'Segoe UI', sans-serif; }
        .form-container { max-width: 400px; margin: 60px auto; background: #22223b; padding: 32px 28px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.2); }
        h2 { text-align: center; margin-bottom: 18px; }
        .otp-inputs { display: flex; gap: 10px; justify-content: center; margin: 15px 0; }
        .otp-inputs input { width: 40px; height: 40px; text-align: center; font-size: 18px; border: 1px solid #ddd; border-radius: 4px; background: #1a1a2e; color: white; }
        .otp-inputs input:focus { border-color: #ffcc00; outline: none; }
        .error-message { color: #dc3545; background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin-bottom: 15px; display: none; }
        .success-message { color: #28a745; background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; margin-bottom: 15px; display: none; }
        button[type="submit"] { width: 100%; padding: 12px; background: #ffcc00; color: black; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; transition: all 0.3s; margin-top: 20px; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; }
        button[type="submit"]:hover { background: #fff; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        button[type="submit"]:disabled { background: #ccc; cursor: not-allowed; transform: none; box-shadow: none; }
        .resend-timer { text-align: center; color: #aaa; font-size: 14px; margin: 10px 0; }
        .back-link { text-align: center; margin-top: 10px; }
        .back-link a { color: #ffcc00; text-decoration: none; }
        .back-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="form-container">
    <form id="otpForm" autocomplete="off" onsubmit="return handleOTPSubmit(event)">
        <h2>Email Verification</h2>
        <div id="otpError" class="error-message"></div>
        <div id="otpSuccess" class="success-message"></div>
        <p style="text-align: center; color: #ccc; margin-bottom: 15px;">We've sent a verification code to <b><?php echo htmlspecialchars($email); ?></b></p>
        <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
        <div class="otp-inputs">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" required oninput="moveToNext(this)">
        </div>
        <button type="submit" id="verifyButton">Verify Code</button>
        <div class="resend-timer">Resend code in <span id="timer">60</span>s</div>
        <div class="back-link"><a href="signup.php">Back to signup</a></div>
    </form>
</div>
<script>
function moveToNext(input) {
    if (input.value.length === 1) {
        const next = input.nextElementSibling;
        if (next) next.focus();
    }
}
function showError(msg) {
    const err = document.getElementById('otpError');
    err.textContent = msg;
    err.style.display = 'block';
    document.getElementById('otpSuccess').style.display = 'none';
}
function showSuccess(msg) {
    const succ = document.getElementById('otpSuccess');
    succ.textContent = msg;
    succ.style.display = 'block';
    document.getElementById('otpError').style.display = 'none';
}
function resetOTPInputs() {
    document.querySelectorAll('.otp-inputs input').forEach(i => { i.value = ''; i.disabled = false; });
    document.querySelector('.otp-inputs input').focus();
}
async function handleOTPSubmit(event) {
    event.preventDefault();
    const form = document.getElementById('otpForm');
    const btn = document.getElementById('verifyButton');
    const otpInputs = document.querySelectorAll('.otp-inputs input');
    let otp = [];
    otpInputs.forEach(input => { otp.push(input.value.trim()); });
    if (otp.some(d => d.length !== 1 || !/^[0-9]$/.test(d))) {
        showError('Please enter a valid 6-digit verification code');
        return false;
    }
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    const formData = new FormData();
    formData.append('email', form.querySelector('input[name="email"]').value);
    otp.forEach(d => formData.append('otp[]', d));
    try {
        const res = await fetch('verify_otp.php', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
            showSuccess(data.message || 'Verification successful!');
            otpInputs.forEach(i => { i.disabled = true; });
            btn.style.display = 'none';
            setTimeout(() => { window.location.href = 'welcome.php'; }, 1500);
        } else {
            showError(data.message || 'Invalid verification code. Please try again.');
            btn.disabled = false;
            btn.textContent = 'Verify Code';
            resetOTPInputs();
        }
    } catch (e) {
        showError('Something went wrong. Please try again.');
        btn.disabled = false;
        btn.textContent = 'Verify Code';
    }
    return false;
}
// Timer for resend
let timeLeft = 60;
const timerSpan = document.getElementById('timer');
const timer = setInterval(() => {
    timeLeft--;
    timerSpan.textContent = timeLeft;
    if (timeLeft <= 0) {
        clearInterval(timer);
        document.querySelector('.resend-timer').innerHTML = '<a href="#" onclick="resendOTP();return false;" style="color:#ffcc00;">Resend code</a>';
    }
}, 1000);
document.querySelector('.otp-inputs input').focus();
async function resendOTP() {
    const email = '<?php echo htmlspecialchars($email); ?>';
    try {
        const res = await fetch('resend_otp.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'email=' + encodeURIComponent(email) });
        const data = await res.json();
        if (data.success) {
            showSuccess('A new verification code has been sent.');
            resetOTPInputs();
            timeLeft = 60;
            timerSpan.textContent = timeLeft;
            document.querySelector('.resend-timer').innerHTML = 'Resend code in <span id="timer">60</span>s';
        } else {
            showError(data.message || 'Failed to resend code.');
        }
    } catch (e) {
        showError('Failed to resend code.');
    }
}
</script>
</body>
</html> 