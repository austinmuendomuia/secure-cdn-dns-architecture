<?php
require __DIR__ . '/config.php';
$msg = '';
$ok = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $e = trim($_POST['email'] ?? '');
    $p = $_POST['password'] ?? '';
    if (!preg_match('/^[A-Za-z0-9_]{3,20}$/', $u)) {
        $msg = 'Username must be 3-20 letters, numbers or underscores.';
    } elseif (!filter_var($e, FILTER_VALIDATE_EMAIL)) {
        $msg = 'Invalid email address.';
    } elseif (strlen($p) < 8) {
        $msg = 'Password must be at least 8 characters.';
    } else {
        $hash = password_hash($p, PASSWORD_ARGON2ID);
        $stmt = $conn->prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, "staff")');
        $stmt->bind_param('sss', $u, $e, $hash);
        if ($stmt->execute()) {
            $ok = true;
            $msg = 'Account created. You can now sign in.';
        } else {
            $msg = 'Username or email already exists.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register — StaffOnly</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="auth-box">
    <h2>Create Staff Account</h2>
    <?php if ($msg): ?><div class="msg <?= $ok ? 'ok' : 'err' ?>"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="post">
        <label>Username</label>
        <input name="username" required maxlength="20" pattern="[A-Za-z0-9_]{3,20}">
        <label>Email</label>
        <input name="email" type="email" required>
        <label>Password</label>
        <input id="pw" name="password" type="password" required minlength="8">
        <div class="meter-bar"><div id="fill" class="meter-fill"></div></div>
        <div id="label" class="meta" style="margin-bottom:14px;">Enter a password</div>
        <button type="submit" style="width:100%">Register</button>
    </form>
    <p class="meta" style="margin-top:16px;text-align:center;">
        Already registered? <a href="login.php">Sign In</a>
    </p>
</div>
<script>
const pw = document.getElementById('pw'), fill = document.getElementById('fill'), lbl = document.getElementById('label');
pw.addEventListener('input', () => {
    const v = pw.value;
    let s = 0;
    if (v.length >= 8) s++;
    if (v.length >= 12) s++;
    if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
    if (/[0-9]/.test(v)) s++;
    if (/[^A-Za-z0-9]/.test(v)) s++;
    const map = [['0%','#334155','Enter a password'],['25%','#ef4444','Weak'],['50%','#f59e0b','Fair'],['75%','#3b82f6','Strong'],['100%','#22c55e','Very strong']];
    const [w,c,t] = map[Math.min(s, 4)];
    fill.style.width = v ? w : '0%'; fill.style.background = c; lbl.textContent = v ? t : 'Enter a password';
});
</script>
</body>
</html>
