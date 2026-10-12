<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Controller\Admin;

// PrestaShop 9 has PrestaShopAdminController; 8.x has FrameworkBundleAdminController
// (still there in 9, deprecated). Pick the one the shop has.
class_alias(
    class_exists(\PrestaShopBundle\Controller\Admin\PrestaShopAdminController::class)
        ? \PrestaShopBundle\Controller\Admin\PrestaShopAdminController::class
        : \PrestaShopBundle\Controller\Admin\FrameworkBundleAdminController::class,
    __NAMESPACE__ . '\\BaseController'
);
