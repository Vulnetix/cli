<?php

class Sid {
    public function handle($request, $next) {
~>        $request->session()->setId($request->input('sid'));
        return $next($request);
    }
}
