<?php
session_start();
if (!isset($_SESSION['username'])) {
    header('Location: login.php');
    exit;
}
require __DIR__ . '/config.php';

$user = $_SESSION['username'];
$isAdmin = ($_SESSION['role'] ?? 'staff') === 'admin';

// Encryption-at-rest key derived from server secret (AES-256-GCM)
$vaultKey = hash('sha256', 'StaffOnly_Vault_Key_2026_' . __DIR__, true);

function encryptNote(string $plain, string $key): string {
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $cipher);
}

function decryptNote(string $b64, string $key): string {
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 28) return '[Unreadable]';
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $plain === false ? '[Decryption failed]' : $plain;
}

// Handle saving or deleting a note
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['new_note'])) {
        $enc = encryptNote(trim($_POST['new_note']), $vaultKey);
        $stmt = $conn->prepare('INSERT INTO notes (username, ciphertext) VALUES (?, ?)');
        $stmt->bind_param('ss', $user, $enc);
        $stmt->execute();
    } elseif (!empty($_POST['delete_id'])) {
        $id = (int)$_POST['delete_id'];
        $stmt = $conn->prepare('DELETE FROM notes WHERE id = ? AND username = ?');
        $stmt->bind_param('is', $id, $user);
        $stmt->execute();
    }
    header('Location: dashboard.php');
    exit;
}

// Fetch only this user's encrypted notes
$stmt = $conn->prepare('SELECT id, ciphertext, created_at FROM notes WHERE username = ? ORDER BY id DESC');
$stmt->bind_param('s', $user);
$stmt->execute();
$myNotes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Admin-only data: Helpdesk Inbox + TLS cert info
$tickets = [];
$tlsInfo = null;
if ($isAdmin) {
    $res = $conn->query('SELECT id, name, email, message, created_at FROM contacts ORDER BY id DESC LIMIT 15');
    if ($res) $tickets = $res->fetch_all(MYSQLI_ASSOC);

    $certPath = '/etc/ssl/zerossl/fullchain.crt';
    if (is_readable($certPath)) {
        $c = openssl_x509_parse(file_get_contents($certPath));
        if ($c) {
            $tlsInfo = [
                'cn' => $c['subject']['CN'] ?? 'staffonly.me',
                'issuer' => $c['issuer']['O'] ?? 'ZeroSSL',
                'expires' => date('Y-m-d', $c['validTo_time_t']),
                'days' => floor(($c['validTo_time_t'] - time()) / 86400)
            ];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal — StaffOnly</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <div class="topbar">
        <div>
            <strong>StaffOnly</strong>
            <span class="meta" style="margin-left:10px;"><?= htmlspecialchars($user) ?></span>
            <span class="role-tag <?= $isAdmin ? 'admin' : '' ?>"><?= $isAdmin ? 'Admin' : 'Staff' ?></span>
        </div>
        <div class="nav">
            <a href="contact.php">IT Helpdesk</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>My Encrypted Notes</h2>
            <p class="meta" style="margin-top:-8px;margin-bottom:14px;">Stored in MariaDB with AES-256-GCM encryption at rest. Only visible to your account.</p>
            <form method="post">
                <textarea name="new_note" rows="3" placeholder="Write a private staff note..." required></textarea>
                <button type="submit">Save Encrypted Note</button>
            </form>
            <div style="margin-top:18px;">
                <?php if (empty($myNotes)): ?>
                    <p class="meta">No notes saved yet.</p>
                <?php else: ?>
                    <?php foreach ($myNotes as $n): ?>
                        <div class="note-item">
                            <div>
                                <div><?= nl2br(htmlspecialchars(decryptNote($n['ciphertext'], $vaultKey))) ?></div>
                                <div class="meta"><?= htmlspecialchars($n['created_at']) ?></div>
                            </div>
                            <form method="post" style="margin:0;">
                                <input type="hidden" name="delete_id" value="<?= (int)$n['id'] ?>">
                                <button type="submit" class="btn-small">Delete</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <?php if ($isAdmin): ?>
        <div class="card">
            <h2>Admin: IT Helpdesk Inbox</h2>
            <?php if (empty($tickets)): ?>
                <p class="meta">No support tickets submitted.</p>
            <?php else: ?>
                <table>
                    <thead><tr><th>From</th><th>Message</th><th>Date</th></tr></thead>
                    <tbody>
                        <?php foreach ($tickets as $t): ?>
                        <tr>
                            <td><?= htmlspecialchars($t['name']) ?><div class="meta"><?= htmlspecialchars($t['email']) ?></div></td>
                            <td><?= htmlspecialchars($t['message']) ?></td>
                            <td class="meta"><?= htmlspecialchars($t['created_at']) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <?php if ($isAdmin && $tlsInfo): ?>
    <div class="footer-meta">
        TLS Certificate: <?= htmlspecialchars($tlsInfo['cn']) ?> &middot; Issuer: <?= htmlspecialchars($tlsInfo['issuer']) ?> &middot; Expires: <?= htmlspecialchars($tlsInfo['expires']) ?> (<?= (int)$tlsInfo['days'] ?> days left)
    </div>
    <?php endif; ?>
</div>
</body>
</html>
