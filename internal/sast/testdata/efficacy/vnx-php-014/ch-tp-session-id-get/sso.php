<?php
if (isset($_GET['PHPSESSID'])) {
~>    session_id($_GET['PHPSESSID']);
}
session_start();
