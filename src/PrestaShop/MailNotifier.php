<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\PrestaShop;

use Ruvelo\PrestaShop\SecurityAlerts\Mail\MessageBuilder;
use Ruvelo\PrestaShop\SecurityAlerts\Notifier;

/**
 * Sends the alert with PrestaShop's own mailer (so the shop's SMTP settings apply).
 */
final class MailNotifier implements Notifier
{
    public const TEMPLATE = 'ruvelo_securityalerts';

    public function __construct(private readonly string $moduleDirectory)
    {
    }

    public function send(array $recipients, array $findings): bool
    {
        $context = \Context::getContext();
        $idLang = (int) \Configuration::get('PS_LANG_DEFAULT');
        $iso = (string) \Language::getIsoById($idLang);
        $this->ensureTemplates($iso);
        $shop = (string) \Configuration::get('PS_SHOP_NAME');

        $sent = true;
        foreach ($recipients as $to) {
            $sent = (bool) \Mail::Send(
                $idLang,
                self::TEMPLATE,
                MessageBuilder::subject($findings, $shop),
                ['{findings_html}' => MessageBuilder::html($findings), '{findings_text}' => MessageBuilder::text($findings)],
                $to,
                null,
                null,
                null,
                null,
                null,
                $this->moduleDirectory . '/mails/',
                false,
                $context->shop->id ?? null,
            ) && $sent;
        }

        return $sent;
    }

    /**
     * PrestaShop looks for mails/<iso>/<template>; only English ships, so the other
     * languages the shop uses get the same files.
     */
    private function ensureTemplates(string $iso): void
    {
        if ($iso === '' || preg_match('/^[a-z]{2,3}(-[a-z]{2})?$/i', $iso) !== 1) {
            return;
        }

        $target = $this->moduleDirectory . '/mails/' . $iso;
        if (is_dir($target)) {
            return;
        }

        @mkdir($target, 0775, true);
        foreach (['html', 'txt'] as $extension) {
            @copy($this->moduleDirectory . '/mails/en/' . self::TEMPLATE . '.' . $extension, $target . '/' . self::TEMPLATE . '.' . $extension);
        }
    }
}
