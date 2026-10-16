<?php

class Text {
    public function upper($s) {
        return preg_replace_callback('/\b(\w)/', function ($m) { return strtoupper($m[1]); }, $s);
    }
}
