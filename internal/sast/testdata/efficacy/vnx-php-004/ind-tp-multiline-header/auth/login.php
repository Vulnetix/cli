<?php
if ($ok) {
~>    header(
        "Location: " . $_POST["back"]
    );
    exit;
}
