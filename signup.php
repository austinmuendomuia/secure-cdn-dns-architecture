<?php
require __DIR__ . '/config.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    if ($username === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
        $msg = 'Invalid input.';
    } else {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $username, $email, $hash);
        $msg = $stmt->execute() ? 'Registration successful.' : 'Username or email already exists.';
    }
}
?>
<!DOCTYPE html>
<html><body>
<h2>Sign up</h2>
<p><?= htmlspecialchars($msg) ?></p>
<form method="post">
<input name="username" placeholder="Username" required>
<input name="email" type="email" placeholder="Email" required>
<input name="password" type="password" minlength="8" placeholder="Password" required>
<button type="submit">Register</button>
</form>
</body></html>
