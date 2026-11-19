<?php
require __DIR__ . '/config.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $stmt = $conn->prepare('SELECT password FROM users WHERE username = ?');
    $stmt->bind_param('s', $u);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $msg = ($row && password_verify($_POST['password'] ?? '', $row['password'])) ? 'Login successful.' : 'Invalid credentials.';
}
?>
<!DOCTYPE html>
<html><body>
<h2>Login</h2>
<p><?= htmlspecialchars($msg) ?></p>
<form method="post">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</body></html>
