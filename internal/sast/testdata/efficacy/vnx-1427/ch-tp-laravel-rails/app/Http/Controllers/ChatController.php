<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use OpenAI\Laravel\Facades\OpenAI;

class ChatController extends Controller
{
    public function ask(Request $request)
    {
        $result = OpenAI::chat()->create([
            'model' => 'gpt-4o-mini',
            'messages' => [
~>                ['role' => 'system', 'content' => $request->input('instructions')],
                ['role' => 'user', 'content' => $request->input('q')],
            ],
        ]);
        return $result->choices[0]->message->content;
    }
}
