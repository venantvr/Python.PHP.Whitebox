<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    // VULN: DB::select with interpolated request input
    public function search(Request $request)
    {
        $q = $request->input('q');
        return DB::select("SELECT * FROM users WHERE name LIKE '%{$q}%'");
    }

    // SAFE: bound parameters
    public function searchSafe(Request $request)
    {
        $q = $request->input('q');
        return DB::select("SELECT * FROM users WHERE name LIKE ?", ['%' . $q . '%']);
    }

    // VULN: whereRaw with request()->get()
    public function filter()
    {
        $col = request()->get('col');
        return \DB::table('users')->whereRaw("$col = 1")->get();
    }

    // VULN: open redirect via redirect($url) helper
    public function go(Request $request)
    {
        return redirect($request->query('next'));
    }

    // VULN: magic property access on the request object reaches echo
    public function show(Request $request)
    {
        echo $request->name;
        echo e($request->name);   // SAFE
    }

    // VULN: path traversal in Storage::get with request input
    public function download(Request $request)
    {
        return \Storage::get('exports/' . $request->file_name);
    }
}
