<?php
function reset_password($email, $newPassword) {
~>    error_log("Password reset for $email: $newPassword");
}
