<?php
~>$host = gethostbyaddr($_SERVER['REMOTE_ADDR']);
if (preg_match('/\.example\.com$/', $host)) {
    show_admin();
}
