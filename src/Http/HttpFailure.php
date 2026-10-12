<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Http;

use Psr\Http\Client\ClientExceptionInterface;

final class HttpFailure extends \RuntimeException implements ClientExceptionInterface
{
}
