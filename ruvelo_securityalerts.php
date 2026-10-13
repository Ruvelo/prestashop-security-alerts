<?php

/**
 * Ruvelo Security Alerts: tells you when PrestaShop or an installed module has a known vulnerability.
 *
 * @author    Ruvelo
 * @copyright Ruvelo
 * @license   https://opensource.org/licenses/MIT MIT
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

// The module ships its own vendor/. Let PrestaShop's classes win where both have one
// (Symfony, PSR interfaces, composer/semver), and only fill in what the shop lacks.
$ruveloSecurityAlertsLoader = require_once __DIR__ . '/vendor/autoload.php';
if (is_object($ruveloSecurityAlertsLoader) && method_exists($ruveloSecurityAlertsLoader, 'register')) {
    $ruveloSecurityAlertsLoader->unregister();
    $ruveloSecurityAlertsLoader->register(false);
}
unset($ruveloSecurityAlertsLoader);

use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ConfigurationSettings;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\DbStorage;

class Ruvelo_SecurityAlerts extends Module
{
    public function __construct()
    {
        $this->name = 'ruvelo_securityalerts';
        $this->tab = 'administration';
        $this->version = '1.1.0';
        $this->author = 'Ruvelo';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = ['min' => '8.1.0', 'max' => _PS_VERSION_];
        $this->tabs = [
            [
                'name' => 'Security alerts',
                'class_name' => 'AdminRuveloSecurityAlerts',
                'route_name' => 'ruvelo_securityalerts_index',
                'parent_class_name' => 'AdminAdvancedParameters',
                'visible' => true,
            ],
        ];

        parent::__construct();

        $this->displayName = $this->trans('Security alerts', [], 'Modules.Ruvelosecurityalerts.Admin');
        $this->description = $this->trans('Tells you when PrestaShop or an installed module has a known vulnerability, and which are exploited in the wild.', [], 'Modules.Ruvelosecurityalerts.Admin');
        $this->confirmUninstall = $this->trans('Remove the module and its stored findings?', [], 'Modules.Ruvelosecurityalerts.Admin');
    }

    public function install(): bool
    {
        return parent::install()
            && $this->installTable()
            && $this->registerHook('dashboardZoneOne')
            && Configuration::updateGlobalValue(ConfigurationSettings::ENABLED, 1)
            && Configuration::updateGlobalValue(ConfigurationSettings::EMAILS, '')
            && Configuration::updateGlobalValue(ConfigurationSettings::MIN_SEVERITY, 'medium')
            && Configuration::updateGlobalValue(ConfigurationSettings::SOURCE, 'valtry')
            && Configuration::updateGlobalValue(ConfigurationSettings::CRON_TOKEN, bin2hex(random_bytes(16)));
    }

    public function uninstall(): bool
    {
        foreach ([ConfigurationSettings::ENABLED, ConfigurationSettings::EMAILS, ConfigurationSettings::MIN_SEVERITY, ConfigurationSettings::SOURCE, ConfigurationSettings::CRON_TOKEN, ConfigurationSettings::LAST_CHECK] as $key) {
            Configuration::deleteByName($key);
        }

        $cache = _PS_CACHE_DIR_ . 'ruvelo_securityalerts';
        foreach (glob($cache . '/*.json') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($cache);

        return Db::getInstance()->execute('DROP TABLE IF EXISTS `' . _DB_PREFIX_ . DbStorage::TABLE . '`')
            && parent::uninstall();
    }

    public function isUsingNewTranslationSystem(): bool
    {
        return true;
    }

    private function installTable(): bool
    {
        $sql = (string) file_get_contents(__DIR__ . '/sql/install.sql');
        $sql = str_replace(['PREFIX_', 'ENGINE_TYPE'], [_DB_PREFIX_, _MYSQL_ENGINE_], $sql);

        return (bool) Db::getInstance()->execute($sql);
    }

    /**
     * Dashboard widget: the counts, and a link to the page.
     */
    /**
     * @param array<string, mixed> $params
     */
    public function hookDashboardZoneOne($params): string
    {
        $storage = new DbStorage();
        $findings = $storage->all();
        $exploited = count(array_filter($findings, static fn ($f): bool => $f->isExploited()));
        $last = $storage->lastCheck();

        $this->context->smarty->assign([
            'ruvelo_sa_total' => count($findings),
            'ruvelo_sa_exploited' => $exploited,
            'ruvelo_sa_other' => count($findings) - $exploited,
            'ruvelo_sa_last' => is_array($last) ? ($last['at'] ?? null) : null,
            'ruvelo_sa_incomplete' => is_array($last) && (!empty($last['problems'])),
            'ruvelo_sa_url' => $this->context->link->getAdminLink('AdminRuveloSecurityAlerts'),
        ]);

        return $this->display(__FILE__, 'views/templates/hook/dashboard.tpl');
    }

    /**
     * The settings page (Modules > Configure).
     */
    public function getContent(): string
    {
        $output = '';

        if (Tools::isSubmit('submitRuveloSecurityAlerts')) {
            $emails = (string) Tools::getValue(ConfigurationSettings::EMAILS);
            $valid = ConfigurationSettings::parseEmails($emails);
            if (count($valid) !== count(preg_split('/[\s,;]+/', trim($emails), -1, PREG_SPLIT_NO_EMPTY) ?: [])) {
                $output .= $this->displayError($this->trans('One of the email addresses is not valid.', [], 'Modules.Ruvelosecurityalerts.Admin'));
            } else {
                Configuration::updateGlobalValue(ConfigurationSettings::ENABLED, (int) Tools::getValue(ConfigurationSettings::ENABLED));
                Configuration::updateGlobalValue(ConfigurationSettings::EMAILS, implode(', ', $valid));
                Configuration::updateGlobalValue(ConfigurationSettings::MIN_SEVERITY, ConfigurationSettings::parseSeverity((string) Tools::getValue(ConfigurationSettings::MIN_SEVERITY))->value);
                Configuration::updateGlobalValue(ConfigurationSettings::SOURCE, ConfigurationSettings::parseSource((string) Tools::getValue(ConfigurationSettings::SOURCE)));
                $output .= $this->displayConfirmation($this->trans('Settings saved.', [], 'Modules.Ruvelosecurityalerts.Admin'));
            }
        }

        return $output . $this->renderForm();
    }

    private function renderForm(): string
    {
        $cron = $this->context->link->getModuleLink($this->name, 'cron', ['token' => ConfigurationSettings::token()]);

        $helper = new HelperForm();
        $helper->module = $this;
        $helper->table = $this->table;
        $helper->default_form_language = (int) Configuration::get('PS_LANG_DEFAULT');
        $helper->identifier = $this->identifier;
        $helper->submit_action = 'submitRuveloSecurityAlerts';
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false) . '&configure=' . $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->fields_value = [
            ConfigurationSettings::ENABLED => (int) Configuration::get(ConfigurationSettings::ENABLED),
            ConfigurationSettings::EMAILS => (string) Configuration::get(ConfigurationSettings::EMAILS),
            ConfigurationSettings::MIN_SEVERITY => (string) Configuration::get(ConfigurationSettings::MIN_SEVERITY),
            ConfigurationSettings::SOURCE => ConfigurationSettings::source(),
        ];

        $t = fn (string $s): string => $this->trans($s, [], 'Modules.Ruvelosecurityalerts.Admin');

        return $helper->generateForm([[
            'form' => [
                'legend' => ['title' => $t('Security alerts'), 'icon' => 'icon-shield'],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $t('Scheduled check and emails'),
                        'name' => ConfigurationSettings::ENABLED,
                        'is_bool' => true,
                        'desc' => $t('Turns off the cron URL and the emails. "Check now" and the console command still work.'),
                        'values' => [
                            ['id' => 'enabled_on', 'value' => 1, 'label' => $t('Yes')],
                            ['id' => 'enabled_off', 'value' => 0, 'label' => $t('No')],
                        ],
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $t('Notification emails'),
                        'name' => ConfigurationSettings::EMAILS,
                        'rows' => 2,
                        'cols' => 40,
                        'desc' => $t('Separate with commas. Empty means no email: the findings are still listed under Advanced Parameters > Security alerts.'),
                    ],
                    [
                        'type' => 'select',
                        'label' => $t('Minimum severity to email'),
                        'name' => ConfigurationSettings::MIN_SEVERITY,
                        'desc' => $t('Flaws exploited in the wild are always emailed. A finding with no rating counts as high.'),
                        'options' => [
                            'query' => [
                                ['id' => 'low', 'name' => $t('Low')],
                                ['id' => 'medium', 'name' => $t('Medium')],
                                ['id' => 'high', 'name' => $t('High')],
                                ['id' => 'critical', 'name' => $t('Critical')],
                            ],
                            'id' => 'id',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'select',
                        'label' => $t('Advisory source'),
                        'name' => ConfigurationSettings::SOURCE,
                        'desc' => $t('Where advisories for PrestaShop and its own modules come from. By default the names of those packages (such as prestashop/prestashop and prestashop/ps_checkout) are sent to Valtry\'s Advisory API, which answers with signed advisories. Versions never leave your server: they are matched here. If Valtry cannot answer, the public feeds (Packagist and CISA) are used automatically. Choose "Public feeds only" to never contact Valtry; setting RUVELO_ADVISORIES_SOURCE=public in the server environment does the same. Third-party modules are always checked against the Friends of Presta advisories.'),
                        'options' => [
                            'query' => [
                                ['id' => 'valtry', 'name' => $t('Valtry, with the public feeds as fallback (default)')],
                                ['id' => 'public', 'name' => $t('Public feeds only (Packagist, CISA)')],
                            ],
                            'id' => 'id',
                            'name' => 'name',
                        ],
                    ],
                ],
                'submit' => ['title' => $t('Save')],
            ],
        ]]) . $this->freeFields($cron);
    }

    /**
     * HelperForm's "free" inputs need their values; they're plain read-only text.
     */
    private function freeFields(string $cron): string
    {
        return '<div class="panel"><div class="panel-heading">' . $this->trans('Run it from cron or a deploy', [], 'Modules.Ruvelosecurityalerts.Admin') . '</div>'
            . '<p><strong>' . $this->trans('Cron URL', [], 'Modules.Ruvelosecurityalerts.Admin') . '</strong><br><code>' . htmlspecialchars($cron, ENT_QUOTES) . '</code></p>'
            . '<p><strong>' . $this->trans('Console command', [], 'Modules.Ruvelosecurityalerts.Admin') . '</strong><br><code>bin/console ruvelo:security-alerts:check --json --fail-on=exploited</code></p></div>';
    }
}
