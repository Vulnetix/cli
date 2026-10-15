<form>
~>  <input name="email" value="<?php echo $_POST['email']; ?>">
~>  <input name="q" value="<?= isset($_GET['q']) ? $_GET['q'] : '' ?>">
</form>
