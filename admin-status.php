<?php
require __DIR__ . '/config.php';
$given = $_GET['key'] ?? '';
if (!isset($ADMIN_KEY) || !hash_equals($ADMIN_KEY, $given)) {
    http_response_code(404);
    exit('Not Found');
}
$uptime = shell_exec('/usr/bin/uptime -p');
$load = shell_exec('/usr/bin/uptime');
$mem = shell_exec('/usr/bin/free -h');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>Server status</title>
<style>
body { font-family: Arial, sans-serif; max-width: 700px; margin: 40px auto; }
pre { background: #111; color: #0f0; padding: 12px; overflow-x: auto; }
</style>
</head>
<body>
<h2>Server status (refreshes every 5 seconds)</h2>
<h3>Uptime</h3>
<pre><?= htmlspecialchars($uptime ?? 'unavailable') ?></pre>
<h3>Load</h3>
<pre><?= htmlspecialchars($load ?? 'unavailable') ?></pre>
<h3>Memory</h3>
<pre><?= htmlspecialchars($mem ?? 'unavailable') ?></pre>
</body>
</html>