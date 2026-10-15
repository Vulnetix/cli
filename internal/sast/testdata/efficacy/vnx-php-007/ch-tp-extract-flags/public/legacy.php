<?php
~>extract($_POST, EXTR_OVERWRITE);
~>@extract($_REQUEST, EXTR_SKIP);
~>extract(array_map('trim', $_GET));
