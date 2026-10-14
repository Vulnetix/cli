<?php
foreach ($_POST as $key => $value) {
~>    $$key = $value;
}
foreach ($_GET as $k => $v)
~>    ${$k} = trim($v);
