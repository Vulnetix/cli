<?php
~>header(sprintf('Location: %s', $_GET['url']));
~>header("Refresh: 3; URL=" . $_GET['next']);
