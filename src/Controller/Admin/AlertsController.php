<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Controller\Admin;

use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ConfigurationSettings;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\DbStorage;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ServiceFactory;
use Ruvelo\PrestaShop\SecurityAlerts\SourceLabel;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Advanced Parameters > Security alerts.
 */
final class AlertsController extends BaseController
{
    private const PAGE = 'AdminRuveloSecurityAlerts';
    private const CSRF = 'ruvelo_securityalerts_check';

    public function indexAction(Request $request): Response
    {
        $this->denyUnless('read');

        $storage = new DbStorage();
        $last = $storage->lastCheck();
        $findings = $storage->all();

        return $this->render('@Modules/ruvelo_securityalerts/views/templates/admin/index.html.twig', [
            'layoutTitle' => 'Security alerts',
            'findings' => array_map(static fn ($f): array => $f->toArray(), $findings),
            'exploitedCount' => \count(array_filter($findings, static fn ($f): bool => $f->isExploited())),
            'last' => $last,
            'sourceLabel' => SourceLabel::of(\is_array($last) && \is_string($last['source'] ?? null) ? $last['source'] : ConfigurationSettings::source()),
            'sourceKnown' => \is_array($last) && \is_string($last['source'] ?? null),
            'checkUrl' => $this->generateUrl('ruvelo_securityalerts_check'),
            'cronUrl' => \Context::getContext()->link->getModuleLink('ruvelo_securityalerts', 'cron', ['token' => ConfigurationSettings::token()]),
            'configUrl' => \Context::getContext()->link->getAdminLink('AdminModules', true, [], ['configure' => 'ruvelo_securityalerts']),
            'csrfName' => self::CSRF,
        ]);
    }

    public function checkAction(Request $request): RedirectResponse
    {
        $this->denyUnless('update');

        if (!$this->isCsrfTokenValid(self::CSRF, (string) $request->request->get('_csrf_token'))) {
            $this->addFlash('error', 'The security token has expired. Try again.');

            return $this->redirectToRoute('ruvelo_securityalerts_index');
        }

        try {
            $outcome = ServiceFactory::checker()->run(false, true);
            $this->addFlash('success', sprintf(
                'Checked %d packages: %d findings, %d exploited.',
                $outcome->report->packageCount(),
                \count($outcome->report->findings),
                \count($outcome->report->exploited()),
            ) . ' Advisory source: ' . SourceLabel::of($outcome->report->source) . '.');
            foreach ($outcome->report->problems as $problem) {
                $this->addFlash('warning', $problem);
            }
        } catch (\Throwable $e) {
            $this->addFlash('error', 'The check failed: ' . $e->getMessage());
        }

        return $this->redirectToRoute('ruvelo_securityalerts_index');
    }

    private function denyUnless(string $level): void
    {
        if (!$this->isGranted($level, self::PAGE)) {
            throw new AccessDeniedException('You do not have access to the security alerts.');
        }
    }
}
