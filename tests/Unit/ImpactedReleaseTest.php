<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Sources\ImpactedRelease;

final class ImpactedReleaseTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string|null, string|null}>
     */
    public static function lines(): iterable
    {
        yield 'upper bound with fix' => ['<= 4.0.1 (4.0.2 fixed the vulnerability)', '<=4.0.1', '4.0.2'];
        yield 'no space' => ['<=4.1.6 (4.1.7 fixed the vulnerability)', '<=4.1.6', '4.1.7'];
        yield 'strictly below' => ['< 1.178.36 (1.178.36 fixed the vulnerability)', '<1.178.36', '1.178.36'];
        yield 'range with and' => ['>= 4.0.0 and < 4.3.03 (4.3.03 fixed issue)', '>=4.0.0,<4.3.03', '4.3.03'];
        yield 'range with ampersand' => ['>= 4.5.18 & <= 4.6.12 (4.6.13 fixed the vulnerability)', '>=4.5.18,<=4.6.12', '4.6.13'];
        yield 'all versions' => ['All versions (at least 2.5.5)', '*', null];
        yield 'all versions, shouting' => ['ALL VERSIONS DANGER', '*', null];
        yield 'two release lines, no fix named for both' => ['<= 6.4.1 (6.4.2 fix the vulnerability) / <= 3.18.0 (3.18.1 fix the vulnerability)', '<=6.4.1|<=3.18.0', null];
        yield 'v prefix' => ['< 6.4.0 / < v3.8.1', '<6.4.0|<3.8.1', null];
        yield 'exact' => ['= 1.0.0', '=1.0.0', null];
        yield 'markdown noise' => ['**<= 2.1.4** (latest version)', '<=2.1.4', null];
        yield 'lower bound then two upper bounds is ambiguous' => ['>= 1.3.0, < 4.4.1, < 5.0.5 (see version details below)', null, null];
        yield 'platform prose' => ['PS 1.5/1.6 : < 1.8.12 (fixed in version 1.8.12), PS 1.7 : < 2.0.3', null, null];
        yield 'letters in version' => ['<= 7.8.a (ALL VERSIONS)', null, null];
        yield 'no operator' => ['from 1.7 to 8.2.2 - fixed in 8.2.3', null, null];
        yield 'empty' => ['', null, null];
    }

    #[DataProvider('lines')]
    public function testParse(string $line, ?string $constraint, ?string $fixed): void
    {
        $parsed = ImpactedRelease::parse($line);

        if ($constraint === null) {
            self::assertNull($parsed);

            return;
        }

        self::assertNotNull($parsed);
        self::assertSame($constraint, $parsed['constraint']);
        self::assertSame($fixed, $parsed['fixed']);
    }
}
