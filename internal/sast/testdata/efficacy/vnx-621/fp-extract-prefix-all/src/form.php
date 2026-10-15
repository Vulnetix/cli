<?php
extract($_POST, EXTR_PREFIX_ALL, 'form');
echo htmlspecialchars($form_name);
