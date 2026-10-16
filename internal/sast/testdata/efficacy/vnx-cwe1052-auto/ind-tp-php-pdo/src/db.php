<?php
function db($user, $pass) {
~>    return new PDO('mysql:host=10.0.0.21;dbname=shop', $user, $pass);
}
