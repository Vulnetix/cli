<?php
$action = $_GET['action'] ?? 'status';
$command = match ($action) {
    'start' => 'systemctl start worker',
    'stop' => 'systemctl stop worker',
    default => 'systemctl status worker',
};
exec($command, $out);
