<?php
class Repo
{
    public function byId(PDO $pdo, $request)
    {
        $stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");
        $stmt->execute([$_GET['id']]);
        $rows = DB::select('select * from users where id = ?', [$request->input('id')]);
        $q = $pdo->prepare('SELECT * FROM t WHERE name = :name');
        $q->bindValue(':name', $_POST['name']);
        return $q->execute();
    }
}
