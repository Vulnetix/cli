<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class LocaleController extends Controller
{
    public function update(Request $request)
    {
        $locale = $request->input('locale');
        session(['locale' => $locale]);
        $request->session()->put('filter', $request->query('filter'));
        Session::put('last_search', $request->input('q'));
        $_SESSION['flash'] = $_POST['message'] ?? '';
        $_SESSION['cart'][$_POST['sku']] = (int) $_POST['qty'];
        $seen = $_SESSION[$_GET['key']] ?? null;
        if (isset($_SESSION[$_COOKIE['k']])) {
            return $seen;
        }
        return back();
    }
}
