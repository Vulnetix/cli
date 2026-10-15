<?php
if (!hash_equals($expected, $signature)) {
    http_response_code(401);
}
