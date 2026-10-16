<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
~>    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        exit('Invalid request');
    }
    perform_transfer($_POST['to'], (int) $_POST['amount']);
}
