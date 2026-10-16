<?php
require_once "lang/" . basename($_GET['lang'] ?? 'en') . ".php";

$step = (int) $_GET['step'];
include "wizard/step" . $step . ".php";
include "wizard/footer" . intval($_GET['variant']) . ".php";
