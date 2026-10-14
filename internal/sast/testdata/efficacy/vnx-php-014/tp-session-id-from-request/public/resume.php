<?php

if (isset($_GET['sid'])) {
~>    session_id($_GET['sid']);
}
~>session_id( $_REQUEST["PHPSESSID"] );
session_start();
