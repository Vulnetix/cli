<?php
function remote_login($user, $pass) {
~>    $url = "https://sso.example.com/check?user=$user&password=$pass";
    return file_get_contents($url);
}

function key_url($apiKey) {
~>    return 'https://api.example.com/v1?api_key=' . $apiKey;
}
?>
<!-- a password form submitted as GET -->
~><form action="login.php" method="get">
  <input type="text" name="user">
  <input type="password" name="password">
</form>
