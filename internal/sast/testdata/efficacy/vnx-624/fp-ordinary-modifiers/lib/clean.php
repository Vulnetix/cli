<?php
$slug = preg_replace('/[^a-z0-9]+/i', '-', $title);
$html = preg_replace("#<script.*?>.*?</script>#is", '', $html);
$name = preg_replace('/\s+/u', ' ', $_POST['name']);
$mail = preg_replace('/(@)example\.com$/', '$1example.org', $mail);
$x = preg_replace('/[aeiou]/', '', $word);
