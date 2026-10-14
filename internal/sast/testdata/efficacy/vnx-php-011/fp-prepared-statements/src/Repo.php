<?php

class Repo
{
    public function find(PDO $pdo)
    {
        $name = $_POST['name'];
        $stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
        $stmt->execute(['name' => $name]);

        $id = $_GET['id'];
        $res = pg_query_params($this->conn, 'SELECT * FROM t WHERE id = $1', [$id]);

        $st = $this->mysqli->prepare('SELECT id FROM users WHERE email = ?');
        $st->bind_param('s', $_POST['email']);
        return $stmt->fetchAll();
    }

    public function laravel($request)
    {
        return DB::select('SELECT * FROM orders WHERE status = ?', [$request->input('status')]);
    }
}
