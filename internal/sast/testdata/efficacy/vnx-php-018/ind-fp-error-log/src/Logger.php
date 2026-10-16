<?php
function logRequest() {
    error_log(print_r($_SERVER, true));
}
