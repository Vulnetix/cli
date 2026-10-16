<?php
function store_upload(array $file): string {
~>    // FIXME: filename is not sanitised, path traversal possible
    $dest = __DIR__ . '/uploads/' . $file['name'];
    move_uploaded_file($file['tmp_name'], $dest);
~>    # TODO need input validation on size
    return $dest;
}
