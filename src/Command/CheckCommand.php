<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Command;

use Ruvelo\PrestaShop\SecurityAlerts\Checker;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ServiceFactory;
use Ruvelo\PrestaShop\SecurityAlerts\SourceLabel;
use Ruvelo\SecurityAdvisories\Exceptions\InvalidThreshold;
use Ruvelo\SecurityAdvisories\Threshold;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * bin/console ruvelo:security-alerts:check [--json] [--fail-on=exploited] [--dry-run]
 *
 * Exit codes: 0 fine, 1 a finding met --fail-on, 2 a source couldn't be read in full or an option is wrong.
 */
final class CheckCommand extends Command
{
    /** @var string|null */
    protected static $defaultName = 'ruvelo:security-alerts:check';

    protected function configure(): void
    {
        $this->setName('ruvelo:security-alerts:check')
            ->setDescription('Checks PrestaShop and its modules for known vulnerabilities, stores what changed and emails what is new')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the report as JSON')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit 1 when a finding is at least this bad: exploited, critical, high, medium or any')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only report: store nothing and send no email')
            ->addOption('fresh', null, InputOption::VALUE_NONE, 'Skip the response cache');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $threshold = $input->getOption('fail-on') !== null ? Threshold::parse((string) $input->getOption('fail-on')) : null;
        } catch (InvalidThreshold $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');

            return 2;
        }

        $outcome = ServiceFactory::checker()->run((bool) $input->getOption('dry-run'), (bool) $input->getOption('fresh'));
        $report = $outcome->report;

        if ($input->getOption('json')) {
            $output->writeln((string) json_encode(array_merge($report->toArray(), ['notes' => Checker::noteLines($report)]), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } else {
            $output->writeln(sprintf('%d packages checked, %d findings, %d exploited. Advisory source: %s.', $report->packageCount(), \count($report->findings), \count($report->exploited()), SourceLabel::of($report->source)));
            foreach ($report->findings as $finding) {
                $output->writeln(sprintf(
                    '%s %s %s: %s%s',
                    $finding->isExploited() ? '[EXPLOITED]' : '[' . $finding->severity->label() . ']',
                    $finding->package,
                    $finding->installed,
                    $finding->title,
                    $finding->fixedIn !== null ? ' (fixed in ' . $finding->fixedIn . ')' : '',
                ));
            }
            foreach ($report->problems as $problem) {
                $output->writeln('<comment>' . $problem . '</comment>');
            }
            foreach (Checker::noteLines($report) as $note) {
                $output->writeln('<comment>Not checked, affected versions unreadable: ' . $note . '</comment>');
            }
            if ($outcome->emailed > 0) {
                $output->writeln(sprintf('Emailed %d findings.', $outcome->emailed));
            }
        }

        if ($threshold !== null && $report->failsOn($threshold)) {
            return 1;
        }

        return $report->isComplete() ? 0 : 2;
    }
}
