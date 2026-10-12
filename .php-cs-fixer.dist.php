<?php

// PrestaShop's coding standard (prestashop/php-dev-tools).
$config = new PrestaShop\CodingStandards\CsFixer\Config();

/** @var \Symfony\Component\Finder\Finder $finder */
$finder = $config->setUsingCache(true)->getFinder();
$finder->in(__DIR__)->exclude(['vendor', 'tests/fixtures', 'art'])->notName('index.php');

return $config;
