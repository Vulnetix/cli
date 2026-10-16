<?php

$who = $_REQUEST['who'];
echo <<<HTML
<section>
~>  <b>Welcome $who</b>
</section>
HTML;
