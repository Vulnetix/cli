<?php
~>$cart = unserialize($_COOKIE["cart"]);
~>$prefs = unserialize(base64_decode($_COOKIE["prefs"]));
~>$state = \unserialize( urldecode($_GET["state"]) );
