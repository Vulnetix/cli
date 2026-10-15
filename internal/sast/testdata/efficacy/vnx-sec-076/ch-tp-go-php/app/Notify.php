<?php
use Telegram\Bot\Api;

~>$telegram = new Api('@@sample:[5-7][0-9]{9}:AA[A-Za-z0-9_-]{33}@@');
$telegram->sendMessage(['chat_id' => -1001234567890, 'text' => 'deploy done']);
