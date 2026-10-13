<?php

namespace XcVm\Module\Firewall;

use XcVm\Cli\CommandInterface;
use XcVm\Infrastructure\Database\DatabaseAware;

/**
 * FirewallCronJob — Periodic health-check, brute-force analysis and banlist consistency sync.
 *
 * Runs via console.php cron:firewall_sync every 5 minutes.
 * - Restarts Fail2ban if unexpectedly stopped.
 * - Analyzes login_logs to catch and ban brute-force attackers across Admin/Reseller logins.
 * - Synchronizes active bans from fail2ban-client into XC_VM blocked_ips table.
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallCronJob implements CommandInterface {
	use DatabaseAware;

	public function getName(): string {
		return 'cron:firewall_sync';
	}

	public function getDescription(): string {
		return 'Cron: periodic Fail2ban health check, brute-force audit and banlist consistency sync';
	}

	public function execute(array $rArgs): int {
		if (!FirewallService::isInstalled()) {
			return 0;
		}

		if (!FirewallService::isRunning()) {
			FirewallService::restart();
		}

		$db = self::db();
		$settings = FirewallService::getSettings();
		$panelMaxRetry = max(3, (int) ($settings['jails']['xcvm-panel']['maxretry'] ?? 5));
		$findTime = max(60, (int) ($settings['jails']['xcvm-panel']['findtime'] ?? 600));

		// 1. Audit login_logs for brute force attackers
		try {
			$window = time() - $findTime;
			$res = $db->query(
				'SELECT `login_ip`, COUNT(*) AS `fail_count`
				 FROM `login_logs`
				 WHERE `status` = ? AND `date` >= ?
				 GROUP BY `login_ip`
				 HAVING `fail_count` >= ?',
				'INVALID_LOGIN',
				$window,
				$panelMaxRetry
			);

			if ($res) {
				$rows = $db->get_rows() ?: [];
				foreach ($rows as $row) {
					$badIp = trim((string) ($row['login_ip'] ?? ''));
					if (filter_var($badIp, FILTER_VALIDATE_IP)) {
						FirewallService::logSecurityAlert(
							'xcvm-panel',
							$badIp,
							"Failed login brute-force: {$row['fail_count']} failures within {$findTime}s"
						);
						FirewallService::banIp($badIp, 'xcvm-panel', "Automated brute-force ban ({$row['fail_count']} failed logins)");
					}
				}
			}
		} catch (\Throwable) {
		}

		// 2. Synchronize active Fail2ban bans into blocked_ips
		$status = FirewallService::getJailsStatus();
		if (!empty($status['jails'])) {
			foreach ($status['jails'] as $jail => $jData) {
				foreach ($jData['banned_ips'] ?? [] as $ip) {
					FirewallService::handleActionBan($ip, $jail, 'Periodic sync verification');
				}
			}
		}

		return 0;
	}
}
