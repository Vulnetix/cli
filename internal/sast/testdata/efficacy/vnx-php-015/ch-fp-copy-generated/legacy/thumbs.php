<?php
copy($_FILES['img']['tmp_name'], 'thumbs/' . sha1_file($_FILES['img']['tmp_name']) . '.png');
copy('defaults/avatar.png', 'img/' . $userId . '.png');
