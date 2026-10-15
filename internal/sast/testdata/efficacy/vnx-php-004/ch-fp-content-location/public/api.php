<?php
header('Content-Location: ' . $_SERVER['REQUEST_URI']);
header('X-Redirect-Hint: ' . $_GET['hint']);
