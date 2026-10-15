<?php
class ListController extends Controller
{
    public function index(Request $request)
    {
~>        return Item::query()->orderByRaw($request->input('sort'))->get();
    }

    public function search(Request $request)
    {
        $term = $request->input('q');
~>        return DB::select("SELECT * FROM items WHERE title LIKE '%$term%'");
    }
}
