<?php
echo isset($_GET['debug']) ? 'on' : 'off';
echo empty($_POST['name']) ? 'Missing name' : 'Thanks';
echo count($_FILES) . ' files';
echo !empty($_REQUEST['ajax']) ? '{}' : '<html></html>';
