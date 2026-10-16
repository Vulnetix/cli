<?php

class Template {
    public function render($text, $vars) {
~>        return preg_replace('/\{(\w+)\}/e', '$vars["\\1"]', $text);
    }
}
