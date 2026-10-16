<?php
session_start();
~>$_SESSION = array_merge($_SESSION, $_POST);
