<?php

class Markup
{
    public function code($post)
    {
~>        return preg_replace("|\[code\](.+?)\[/code\]|es", "highlight_string('$1', true)", $post);
    }

    public function vars($content)
    {
~>        return preg_replace('#\{\{(.+?)\}\}#e', '$this->render("$1")', $content);
    }

    public function braces($content)
    {
~>        return preg_replace('{<\?=(.*?)\?>}se', 'eval("return $1;")', $content);
    }

    public function tilde($content)
    {
~>        return preg_replace( '~%(\w+)%~e' , '$_SERVER["$1"]' , $content );
    }
}
