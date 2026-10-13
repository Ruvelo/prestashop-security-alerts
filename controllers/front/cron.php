<?php

/**
 * Secure cron URL: index.php?fc=module&module=ruvelo_securityalerts&controller=cron&token=...
 *
 * @author    Ruvelo
 * @license   MIT
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ConfigurationSettings;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ServiceFactory;

class Ruvelo_SecurityAlertsCronModuleFrontController extends ModuleFrontController
{
    public $ssl = true;
    public $auth = false;

    public function display(): void
    {
        $this->ajax = true;
        header('Content-Type: application/json');
        header('Cache-Control: no-store');

        $token = (string) Tools::getValue('token');
        if ($token === '' || !hash_equals(ConfigurationSettings::token(), $token)) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'Invalid token']);
            exit;
        }

        if (!(new ConfigurationSettings())->isEnabled()) {
            echo json_encode(['ok' => true, 'enabled' => false]);
            exit;
        }

        try {
            $outcome = ServiceFactory::checker()->run();
            echo json_encode([
                'ok' => $outcome->report->isComplete(),
                'findings' => count($outcome->report->findings),
                'exploited' => count($outcome->report->exploited()),
                'emailed' => $outcome->emailed,
                'problems' => count($outcome->report->problems),
                'source' => $outcome->report->source,
            ]);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'The check failed']);
        }
        exit;
    }
}
