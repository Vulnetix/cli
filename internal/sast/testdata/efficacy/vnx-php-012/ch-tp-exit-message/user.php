<?php
if (!user_exists($_GET['user'])) {
~>    exit("Unknown user: " . $_GET['user']);
}
