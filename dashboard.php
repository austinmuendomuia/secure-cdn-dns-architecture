<?php
session_start();
if (!isset($_SESSION['username'])) {
    header('Location: login.php');
    exit;
}

require_once 'config.php';

// 1. Inspect ZeroSSL Certificate
$certPath = '/etc/ssl/zerossl/fullchain.crt';
$certIssuer = 'ZeroSSL';
$daysLeft = 'N/A';
if (is_readable($certPath)) {
    $certData = openssl_x509_parse(file_get_contents($certPath));
    if ($certData) {
        $certIssuer = $certData['issuer']['O'] ?? 'ZeroSSL';
        $daysLeft = floor(($certData['validTo_time_t'] - time()) / 86400) . ' days';
    }
}

// 2. AES-256-GCM Cryptography Workbench
$cryptoResult = '';
$cryptoError = '';
$mode = $_POST['mode'] ?? 'encrypt';
$inputText = $_POST['input_text'] ?? '';
$passphrase = $_POST['passphrase'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['crypto_action'])) {
    if ($inputText === '' || $passphrase === '') {
        $cryptoError = 'Both text and passphrase are required.';
    } else {
        $key = hash('sha256', $passphrase, true);
        if ($mode === 'encrypt') {
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($inputText, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            $cryptoResult = base64_encode($iv . $tag . $cipher);
        } else {
            $raw = base64_decode($inputText, true);
            if ($raw === false || strlen($raw) < 28) {
                $cryptoError = 'Invalid Base64 ciphertext.';
            } else {
                $iv = substr($raw, 0, 12);
                $tag = substr($raw, 12, 16);
                $cipher = substr($raw, 28);
                $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
                if ($plain === false) {
                    $cryptoError = 'Decryption failed: wrong passphrase or tampered data.';
                } else {
                    $cryptoResult = $plain;
                }
            }
        }
    }
}

// 3. Fetch Contact Inbox (supports both PDO and MySQLi from config.php)
$contacts = [];
$dbError = '';
try {
    if (isset($pdo) && $pdo instanceof PDO) {
        $stmt = $pdo->query("SELECT * FROM contacts ORDER BY id DESC LIMIT 10");
        $contacts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } elseif (isset($conn) && $conn instanceof mysqli) {
        $res = $conn->query("SELECT * FROM contacts ORDER BY id DESC LIMIT 10");
        if ($res) $contacts = $res->fetch_all(MYSQLI_ASSOC);
    } elseif (isset($mysqli) && $mysqli instanceof mysqli) {
        $res = $mysqli->query("SELECT * FROM contacts ORDER BY id DESC LIMIT 10");
        if ($res) $contacts = $res->fetch_all(MYSQLI_ASSOC);
    }
} catch (Throwable $e) {
    $dbError = 'Could not load contacts table.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>StaffOnly Ops Portal</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
        .topbar { display: flex; justify-content: space-between; align-items: center; background: #1e293b; padding: 14px 20px; border-radius: 8px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
        .badge { background: #065f46; color: #a7f3d0; padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; }
        .nav a { color: #38bdf8; text-decoration: none; margin-left: 16px; font-weight: 600; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        h2 { margin-top: 0; font-size: 1.2rem; color: #f8fafc; }
        textarea, input, select { width: 100%; box-sizing: border-box; background: #0f172a; color: #f8fafc; border: 1px solid #475569; border-radius: 6px; padding: 10px; margin: 8px 0 14px; font-family: monospace; }
        button { background: #2563eb; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; }
        button:hover { background: #1d4ed8; }
        .output { background: #020617; padding: 12px; border-radius: 6px; word-break: break-all; font-family: monospace; margin-top: 12px; border-left: 4px solid #22c55e; }
        .error { color: #fca5a5; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #334155; word-break: break-word; }
        th { color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="topbar">
        <div>
            <strong>StaffOnly Ops Portal</strong> &mdash; Logged in as <code><?= htmlspecialchars($_SESSION['username']) ?></code>
            <span class="badge">TLS: <?= htmlspecialchars($certIssuer) ?> (<?= htmlspecialchars($daysLeft) ?> left)</span>
        </div>
        <div class="nav">
            <a href="contact.php">Contact Form</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>AES-256-GCM Memo Encryptor</h2>
            <form method="POST">
                <input type="hidden" name="crypto_action" value="1">
                <label>Mode</label>
                <select name="mode">
                    <option value="encrypt" <?= $mode === 'encrypt' ? 'selected' : '' ?>>Encrypt (Plaintext &rarr; Base64)</option>
                    <option value="decrypt" <?= $mode === 'decrypt' ? 'selected' : '' ?>>Decrypt (Base64 &rarr; Plaintext)</option>
                </select>
                <label>Passphrase</label>
                <input type="password" name="passphrase" value="<?= htmlspecialchars($passphrase) ?>" placeholder="Enter shared secret">
                <label>Message / Ciphertext</label>
                <textarea name="input_text" rows="4" placeholder="Enter sensitive memo or Base64 payload..."><?= htmlspecialchars($inputText) ?></textarea>
                <button type="submit">Run AES-256-GCM</button>
            </form>
            <?php if ($cryptoError): ?>
                <div class="error"><?= htmlspecialchars($cryptoError) ?></div>
            <?php elseif ($cryptoResult !== ''): ?>
                <div class="output"><?= htmlspecialchars($cryptoResult) ?></div>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>Recent Contact Inbox (staffonly_db)</h2>
            <?php if ($dbError): ?>
                <div class="error"><?= htmlspecialchars($dbError) ?></div>
            <?php elseif (empty($contacts)): ?>
                <p>No messages in the contacts table yet.</p>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <?php foreach (array_keys($contacts[0]) as $col): ?>
                                <th><?= htmlspecialchars($col) ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($contacts as $row): ?>
                            <tr>
                                <?php foreach ($row as $val): ?>
                                    <td><?= htmlspecialchars((string)$val) ?></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
