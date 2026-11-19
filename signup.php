<?php
require __DIR__ . '/config.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    if (!preg_match('/^[A-Za-z0-9_]{3,20}$/', $username)) {
        $msg = 'Username must be 3-20 letters, numbers or underscores.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
        $msg = 'Invalid email address.';
    } elseif (!preg_match('/^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$/', $password)) {
        $msg = 'Password needs 8+ characters with a letter, a number and a special character.';
    } else {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $username, $email, $hash);
        $msg = $stmt->execute() ? 'Registration successful.' : 'Username or email already exists.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign up</title>
<style>
body { font-family: Arial, sans-serif; max-width: 380px; margin: 40px auto; }
input { display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
button { padding: 10px 16px; }
#bar-wrap { background: #ddd; height: 10px; border-radius: 5px; }
#bar { height: 10px; width: 0; border-radius: 5px; transition: width .2s, background .2s; }
#label { font-size: 14px; margin: 4px 0 12px; }
</style>
</head>
<body>
<h2>Sign up</h2>
<p><?= htmlspecialchars($msg) ?></p>
<form method="post">
<input name="username" placeholder="Username" required minlength="3" maxlength="20" pattern="[A-Za-z0-9_]{3,20}" title="3-20 letters, numbers or underscores">
<input name="email" type="email" placeholder="Email" required maxlength="100">
<input id="password" name="password" type="password" placeholder="Password" required minlength="8" maxlength="72" pattern="(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}" title="8+ characters with a letter, a number and a special character">
<div id="bar-wrap"><div id="bar"></div></div>
<p id="label">Enter a password</p>
<button type="submit">Register</button>
</form>
<script>
const pw = document.getElementById('password');
const bar = document.getElementById('bar');
const label = document.getElementById('label');
const colors = ['#cccccc', '#d9534f', '#e67e22', '#f1c40f', '#9acd32', '#2ecc71'];
const names = ['Enter a password', 'Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
pw.addEventListener('input', () => {
  const v = pw.value;
  let s = 0;
  if (v.length >= 8) s++;
  if (v.length >= 12) s++;
  if (/\d/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
  if (v.length === 0) s = 0;
  bar.style.width = (s * 20) + '%';
  bar.style.background = colors[s];
  label.textContent = names[s];
});
</script>
</body>
</html>