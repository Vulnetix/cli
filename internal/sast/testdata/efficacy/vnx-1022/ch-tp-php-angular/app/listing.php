<?php foreach ($rows as $row): ?>
~>  <a href="<?= htmlspecialchars($row['url']) ?>" target="_blank"><?= htmlspecialchars($row['title']) ?></a>
<?php endforeach; ?>
