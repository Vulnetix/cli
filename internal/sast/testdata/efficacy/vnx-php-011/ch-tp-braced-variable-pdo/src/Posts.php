<?php
class Posts
{
    public function delete(PDO $pdo)
    {
        $id = $_REQUEST['id'];
~>        $pdo->query("DELETE FROM posts WHERE id = {$id}");
    }
}
