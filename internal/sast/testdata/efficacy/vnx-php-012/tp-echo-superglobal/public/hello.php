<?php

~>echo "Hello " . $_GET['name'];
~>echo 'Search results for: ', $_REQUEST['q'], '</h2>';
~>    echo "<p>{$_POST['comment']}</p>";
~>if (isset($_GET['err'])) { echo $_GET['err']; }
