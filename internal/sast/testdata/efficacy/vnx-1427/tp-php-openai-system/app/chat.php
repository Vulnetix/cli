<?php
$client = OpenAI::client(getenv('OPENAI_API_KEY'));

$persona = $_GET['persona'] ?? 'helpful';
$result = $client->chat()->create([
    'model' => 'gpt-4o',
    'messages' => [
~>        ['role' => 'system', 'content' => "You are a {$persona} assistant."],
        ['role' => 'user', 'content' => $_POST['question']],
    ],
]);

$messages = [
    [
        'role' => 'system',
~>        'content' => 'Answer as ' . $request->input('style'),
    ],
];
