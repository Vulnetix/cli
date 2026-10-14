<?php
// file_get_contents($_GET["url"]) is SSRF
class Controller
{
    public function show($request)
    {
        $value = $this->items->get($request->input("key"));
        $cache = $this->cache->get($_GET["k"]);
        $session = $request->session()->get("x");
        echo "Never call curl_init(\$_GET[\"u\"])";
        $msg = 'file_get_contents($_GET["url"])';
        return $this->filesystem->get($_GET["path"]);
    }
}
