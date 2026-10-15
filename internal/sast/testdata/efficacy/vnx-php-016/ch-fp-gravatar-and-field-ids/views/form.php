<?php
$gravatar = 'https://www.gravatar.com/avatar/' . md5(strtolower(trim($email)));
$passwordFieldId = 'field-' . md5($formId);
$resetToken = bin2hex(random_bytes(32));
$tokenHash = hash('sha256', $resetToken);
