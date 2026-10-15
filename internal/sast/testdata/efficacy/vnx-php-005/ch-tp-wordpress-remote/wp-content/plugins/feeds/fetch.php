<?php
$feed = esc_url_raw($_GET['feed']);
~>$response = wp_remote_get($feed);
~>$posted = wp_remote_post($_POST['endpoint'], ['body' => ['ok' => 1]]);
