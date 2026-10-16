<?php

function app_db(): mysqli
{
~>    $link = mysqli_connect('localhost', 'wp_app', 'Wp-Db-S3cret', 'wordpress');
    if (!$link) {
        die('db down');
    }
    return $link;
}

function reports_pdo(string $dsn): PDO
{
~>    return new PDO($dsn, 'reports', 'Pd0-Rep0rts!', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

function upload_backup(string $file): void
{
    $conn = ftp_connect('backup.example.org');
~>    ftp_login($conn, 'deploy', 'Ftp-D3ploy-1');
    ftp_put($conn, basename($file), $file, FTP_BINARY);
}
