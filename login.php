<?php
session_start();
require __DIR__ . '/config.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $stmt = $conn->prepare('SELECT password, role FROM users WHERE username = ?');
    $stmt->bind_param('s', $u);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if ($row && password_verify($_POST['password'] ?? '', $row['password'])) {
        session_regenerate_id(true);
        $_SESSION['username'] = $u;
        $_SESSION['role'] = $row['role'];
        header('Location: dashboard.php');
        exit;
    } else {
        $msg = 'Invalid credentials.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — StaffOnly</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="auth-box">
    <h2>StaffOnly Login</h2>
    <?php if ($msg): ?><div class="msg err"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="post">
        <label>Username</label>
        <input name="username" required maxlength="20" pattern="[A-Za-z0-9_]{3,20}">
        <label>Password</label>
        <input name="password" type="password" required minlength="8">
        <button type="submit" style="width:100%">Sign In</button>
    </form>
    <p class="meta" style="margin-top:16px;text-align:center;">
        No account? <a href="signup.php">Register</a> &middot; <a href="contact.php">IT Helpdesk</a>
    </p>
</div>
</body>
</html>
