<?php
$data = unserialize($redis->get("session:" . $_COOKIE["sid"]));
