<?php
require __DIR__ . '/config.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $message = trim($_POST['message'] ?? '');
    if (!preg_match('/^[A-Za-z ]{2,50}$/', $name)) {
        $msg = 'Name must be 2-50 letters.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
        $msg = 'Invalid email address.';
    } elseif (strlen($message) < 10 || strlen($message) > 1000) {
        $msg = 'Message must be 10-1000 characters.';
    } else {
        $stmt = $conn->prepare('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $name, $email, $message);
        $msg = $stmt->execute() ? 'Message sent.' : 'Could not save your message.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Contact</title>
<style>
body { font-family: Arial, sans-serif; max-width: 380px; margin: 40px auto; }
input, textarea { display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
button { padding: 10px 16px; }
</style>
</head>
<body>
<h2>Contact us</h2>
<p><?= htmlspecialchars($msg) ?></p>
<form method="post">
<input name="name" placeholder="Your name" required minlength="2" maxlength="50" pattern="[A-Za-z ]{2,50}" title="Letters and spaces only">
<input name="email" type="email" placeholder="Email" required maxlength="100">
<textarea name="message" placeholder="Message" required minlength="10" maxlength="1000" rows="5"></textarea>
<button type="submit">Send</button>
</form>
</body>
</html>