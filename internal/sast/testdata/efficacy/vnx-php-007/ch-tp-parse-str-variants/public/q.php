<?php
~>parse_str($_SERVER['QUERY_STRING']);
~>parse_str(file_get_contents('php://input'));
~>mb_parse_str($_POST['filters']);
