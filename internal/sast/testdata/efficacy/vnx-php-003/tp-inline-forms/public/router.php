<?php
~>include "templates/" . $_GET["tpl"] . ".php";
~>require_once($_REQUEST["module"]);
~>include_once __DIR__ . "/lang/" . $_COOKIE["lang"] . ".php";
~>require "views/{$_POST["view"]}.php";
