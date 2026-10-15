<?php

class Login
{
    public function token(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
        $code = random_int(100000, 999999);
        return $token . $code;
    }

    public function slowDown(): void
    {
        sleep(rand(2, 4));
        $banner = $this->banners[array_rand($this->banners)];
        $x = mt_rand(1, 6);
        echo "Do not build a token with mt_rand()";
    }
}
