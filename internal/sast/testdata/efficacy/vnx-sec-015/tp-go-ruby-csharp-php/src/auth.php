<?php
use Lcobucci\JWT\Configuration;
~>use Lcobucci\JWT\Signer\None;

~>$decoded = JWT::decode($jwt, $key, array('HS256', 'none'));
