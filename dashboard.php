<?php
session_start();
if (!isset($_SESSION['username'])) {
    header('Location: login.php');
    exit;
}
require __DIR__ . '/config.php';

$user = $_SESSION['username'];
$isAdmin = ($_SESSION['role'] ?? 'staff') === 'admin';
$justSaved = isset($_GET['saved']);

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['new_note'])) {
        $enc = encryptNote(trim($_POST['new_note']), $vaultKey);
        $stmt = $conn->prepare('INSERT INTO notes (username, ciphertext) VALUES (?, ?)');
        $stmt->bind_param('ss', $user, $enc);
        $stmt->execute();
        header('Location: dashboard.php?saved=1');
        exit;
    } elseif (!empty($_POST['delete_id'])) {
        $id = (int)$_POST['delete_id'];
        $stmt = $conn->prepare('DELETE FROM notes WHERE id = ? AND username = ?');
        $stmt->bind_param('is', $id, $user);
        $stmt->execute();
        header('Location: dashboard.php');
        exit;
    }
}

$stmt = $conn->prepare('SELECT id, ciphertext, created_at FROM notes WHERE username = ? ORDER BY id DESC');
$stmt->bind_param('s', $user);
$stmt->execute();
$myNotes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$tickets = [];
$tlsInfo = null;
if ($isAdmin) {
    $res = $conn->query('SELECT id, name, email, message, created_at FROM contacts ORDER BY id DESC LIMIT 15');
    if ($res) $tickets = $res->fetch_all(MYSQLI_ASSOC);

    $certPath = '/etc/ssl/zerossl/fullchain.crt';
    if (is_readable($certPath)) {
        $rawCert = file_get_contents($certPath);
        $c = openssl_x509_parse($rawCert);
        if ($c) {
            $pubKeyInfo = 'N/A';
            $pub = openssl_pkey_get_public($rawCert);
            if ($pub) {
                $det = openssl_pkey_get_details($pub);
                $types = [OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_EC => 'ECDSA', OPENSSL_KEYTYPE_DSA => 'DSA'];
                $typeName = $types[$det['type'] ?? -1] ?? 'Unknown';
                $pubKeyInfo = $typeName . ' (' . ($det['bits'] ?? '?') . '-bit)';
            }

            $fpRaw = openssl_x509_fingerprint($rawCert, 'sha256');
            $fp = $fpRaw ? strtoupper(implode(':', str_split($fpRaw, 2))) : 'N/A';

            $tlsInfo = [
                'version'    => 'v' . (($c['version'] ?? 2) + 1),
                'serial'     => strtoupper($c['serialNumberHex'] ?? ($c['serialNumber'] ?? 'N/A')),
                'cn'         => $c['subject']['CN'] ?? 'staffonly.me',
                'sans'       => $c['extensions']['subjectAltName'] ?? 'N/A',
                'issuer'     => trim(($c['issuer']['CN'] ?? '') . ' (' . ($c['issuer']['O'] ?? 'ZeroSSL') . ')'),
                'valid_from' => date('Y-m-d H:i:s T', $c['validFrom_time_t']),
                'valid_to'   => date('Y-m-d H:i:s T', $c['validTo_time_t']),
                'days'       => floor(($c['validTo_time_t'] - time()) / 86400),
                'sig_alg'    => $c['signatureTypeLN'] ?? ($c['signatureTypeSN'] ?? 'N/A'),
                'pub_key'    => $pubKeyInfo,
                'fingerprint'=> $fp,
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
<style>
.saved-toast {
    display: flex;
    align-items: center;
    gap: 14px;
    background: #052e16;
    border: 1px solid #14532d;
    color: #bbf7d0;
    padding: 12px 16px;
    border-radius: 10px;
    margin-bottom: 20px;
}
.saved-toast img {
    width: 56px;
    height: 56px;
    object-fit: cover;
    border-radius: 8px;
    border: 1px solid #22c55e;
}
.cert-table td:first-child {
    color: #94a3b8;
    width: 190px;
    white-space: nowrap;
    font-weight: 500;
}
.cert-table code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.82rem;
    color: #cbd5e1;
    word-break: break-all;
}
</style>
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

    <?php if ($justSaved): ?>
    <div id="savedToast" class="saved-toast">
        <img src="assets/saved.jpg" alt="Note encrypted">
        <div>
            <strong>Note Encrypted &amp; Stored</strong>
            <div class="meta" style="color:#86efac;">Saved to MariaDB using AES-256-GCM encryption at rest.</div>
        </div>
    </div>
    <script>
        setTimeout(() => {
            const el = document.getElementById('savedToast');
            if (el) el.style.display = 'none';
        }, 5000);
    </script>
    <?php endif; ?>

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
    <div class="card" style="margin-top:20px;">
        <h2>Admin: TLS / X.509 Certificate Details</h2>
        <table class="cert-table">
            <tbody>
                <tr><td>Common Name (CN)</td><td><code><?= htmlspecialchars($tlsInfo['cn']) ?></code></td></tr>
                <tr><td>Subject Alt Names (SAN)</td><td><code><?= htmlspecialchars($tlsInfo['sans']) ?></code></td></tr>
                <tr><td>Issuer</td><td><?= htmlspecialchars($tlsInfo['issuer']) ?></td></tr>
                <tr><td>X.509 Version</td><td><?= htmlspecialchars($tlsInfo['version']) ?></td></tr>
                <tr><td>Serial Number</td><td><code><?= htmlspecialchars($tlsInfo['serial']) ?></code></td></tr>
                <tr><td>Valid From</td><td><?= htmlspecialchars($tlsInfo['valid_from']) ?></td></tr>
                <tr><td>Valid Until</td><td><?= htmlspecialchars($tlsInfo['valid_to']) ?> (<?= (int)$tlsInfo['days'] ?> days remaining)</td></tr>
                <tr><td>Signature Algorithm</td><td><code><?= htmlspecialchars($tlsInfo['sig_alg']) ?></code></td></tr>
                <tr><td>Public Key</td><td><code><?= htmlspecialchars($tlsInfo['pub_key']) ?></code></td></tr>
                <tr><td>SHA-256 Fingerprint</td><td><code><?= htmlspecialchars($tlsInfo['fingerprint']) ?></code></td></tr>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>
</body>
</html>
