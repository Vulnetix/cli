<?php
$items = collect($rows);
$one = $items->get($request->input("key"));
$v = Cache::get($request->input("k"));
