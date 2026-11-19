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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login</title>
<style>
body { font-family: Arial, sans-serif; max-width: 380px; margin: 40px auto; }
input { display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
button { padding: 10px 16px; }
</style>
</head>
<body>
<h2>Login</h2>
<p><?= htmlspecialchars($msg) ?></p>
<form method="post">
<input name="username" placeholder="Username" required maxlength="20" pattern="[A-Za-z0-9_]{3,20}" title="3-20 letters, numbers or underscores">
<input name="password" type="password" placeholder="Password" required minlength="8" maxlength="72">
<button type="submit">Login</button>
</form>
</body>
</html>