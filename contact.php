<?php
session_start();
require __DIR__ . '/config.php';
$msg = '';
$ok = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $body = trim($_POST['message'] ?? '');
    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $body === '') {
        $msg = 'Please fill in all fields with a valid email.';
    } else {
        $stmt = $conn->prepare('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $name, $email, $body);
        if ($stmt->execute()) {
            $ok = true;
            $msg = 'Ticket submitted. An administrator will review it shortly.';
        } else {
            $msg = 'Could not submit ticket.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IT Helpdesk — StaffOnly</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="auth-box" style="max-width:480px;">
    <h2>IT Helpdesk</h2>
    <p class="meta" style="margin-top:-8px;margin-bottom:16px;">Submit an issue or request to the StaffOnly administrators.</p>
    <?php if ($msg): ?><div class="msg <?= $ok ? 'ok' : 'err' ?>"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <form method="post">
        <label>Your Name</label>
        <input name="name" required value="<?= htmlspecialchars($_SESSION['username'] ?? '') ?>">
        <label>Email</label>
        <input name="email" type="email" required>
        <label>Issue / Request</label>
        <textarea name="message" rows="4" required></textarea>
        <button type="submit" style="width:100%">Submit Ticket</button>
    </form>
    <p class="meta" style="margin-top:16px;text-align:center;">
        <?php if (isset($_SESSION['username'])): ?>
            <a href="dashboard.php">&larr; Back to Portal</a>
        <?php else: ?>
            <a href="login.php">&larr; Back to Login</a>
        <?php endif; ?>
    </p>
</div>
</body>
</html>
