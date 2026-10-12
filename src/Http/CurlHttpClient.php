<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Http;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A small PSR-18 client on ext-curl, which every PrestaShop has. It exists so the
 * module doesn't bring a second HTTP stack (Guzzle, Symfony HttpClient) into a
 * shop that already has one at another version.
 */
final class CurlHttpClient implements ClientInterface
{
    public function __construct(
        private readonly Psr17Factory $factory = new Psr17Factory(),
        private readonly int $timeout = 20,
    ) {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        if (!\function_exists('curl_init')) {
            throw new HttpFailure('The PHP curl extension is not available.');
        }

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[] = $name . ': ' . implode(', ', $values);
        }

        $handle = curl_init((string) $request->getUri());
        if ($handle === false) {
            throw new HttpFailure('Could not start a curl request.');
        }

        $responseHeaders = [];
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $request->getMethod(),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (\count($parts) === 2) {
                    $responseHeaders[trim($parts[0])] = trim($parts[1]);
                }

                return \strlen($line);
            },
        ]);

        $body = (string) $request->getBody();
        if ($body !== '') {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $result = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);

        if (!\is_string($result)) {
            throw new HttpFailure($error !== '' ? $error : 'No answer.');
        }

        $response = $this->factory->createResponse($status)->withBody($this->factory->createStream($result));
        foreach ($responseHeaders as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
