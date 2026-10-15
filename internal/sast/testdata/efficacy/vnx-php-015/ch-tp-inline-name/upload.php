<?php
if (isset($_FILES['avatar'])) {
~>    move_uploaded_file($_FILES['avatar']['tmp_name'], "uploads/" . $_FILES['avatar']['name']);
}
