<?php
~>$data = file_get_contents('reports/' . $_GET['id'] . '.csv');
~>$fh = fopen("logs/" . $_POST['name'] . ".log", "r");
~>readfile(UPLOAD_DIR . $_GET['f'] . '.pdf');
