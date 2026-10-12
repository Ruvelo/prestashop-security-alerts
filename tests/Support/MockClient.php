<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Answers requests from a map of URL => body, and remembers what was asked.
 */
final class MockClient implements ClientInterface
{
    /** @var list<string> */
    public array $requested = [];

    /**
     * @param array<string, string> $bodies
     */
    public function __construct(private readonly array $bodies)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string) $request->getUri();
        $this->requested[] = $request->getMethod() . ' ' . $url;

        foreach ($this->bodies as $needle => $body) {
            if (str_contains($url, $needle)) {
                return new Response(200, ['Content-Type' => 'application/json'], $body);
            }
        }

        return new Response(404, [], 'not found');
    }
}
