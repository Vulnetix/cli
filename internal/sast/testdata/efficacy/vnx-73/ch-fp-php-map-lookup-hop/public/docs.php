<?php
$docs = [
    'readme' => ['file' => 'README.md'],
    'changes' => ['file' => 'CHANGELOG.md'],
];
$id = isset($_GET['doc']) ? $_GET['doc'] : 'readme';
if (!array_key_exists($id, $docs)) {
    $id = 'readme';
}
$file = $docs[$id]['file'];
echo file_get_contents(__DIR__ . '/' . $file);
