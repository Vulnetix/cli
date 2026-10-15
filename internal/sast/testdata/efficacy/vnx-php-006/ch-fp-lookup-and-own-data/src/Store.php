<?php
class Store
{
    public function load($redis)
    {
        $cached = unserialize($redis->get('user:' . $_GET['id']));
        $row = unserialize(file_get_contents(__DIR__ . '/cache/' . md5($_GET['q'])));
        return $this->serializer->unserialize($_POST['blob']);
    }
}
