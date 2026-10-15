<?php

class Issuer
{
	private const TOKEN_LIFE = 300;

	public function issue_token($signer) {
		$now = time();
		$access_token = $signer->sign(['sub' => 'svc', 'exp' => $now + self::TOKEN_LIFE]);
		return $access_token;
	}
}
