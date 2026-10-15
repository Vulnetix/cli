<?php
namespace App\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LogTailAction
{
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $params = $request->getQueryParams();
        $lines = $params['lines'] ?? '50';
~>        $output = shell_exec('tail -n ' . $lines . ' /var/log/app.log');
        $response->getBody()->write((string) $output);
        return $response;
    }
}
