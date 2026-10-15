<?php
header('Content-Type: application/json');
echo json_encode(['q' => $_GET['q'], 'ok' => true]);
