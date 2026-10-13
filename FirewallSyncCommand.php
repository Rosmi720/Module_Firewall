<?php

namespace XcVm\Module\Firewall;

use XcVm\Cli\CommandInterface;

/**
 * FirewallSyncCommand — Sync Fail2ban actions with XC_VM database and Cluster.
 *
 * Invoked by Fail2ban action (actionban / actionunban):
 *   php console.php firewall:sync ban <ip> <jail>
 *   php console.php firewall:sync unban <ip> <jail>
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallSyncCommand implements CommandInterface {

	public function getName(): string {
		return 'firewall:sync';
	}

	public function getDescription(): string {
		return 'Sync Fail2ban ban/unban events with XC_VM blocked_ips database table';
	}

	public function execute(array $rArgs): int {
		$action = $rArgs[0] ?? '';
		$ip     = $rArgs[1] ?? '';
		$jail   = $rArgs[2] ?? 'unknown';

		if (empty($action) || empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
			echo "Usage: php console.php firewall:sync <ban|unban> <ip> [jail]\n";
			return 1;
		}

		if ($action === 'ban') {
			FirewallService::handleActionBan($ip, $jail);
			echo "Synced BAN for {$ip} (jail: {$jail})\n";
			return 0;
		}

		if ($action === 'unban') {
			FirewallService::handleActionUnban($ip, $jail);
			echo "Synced UNBAN for {$ip} (jail: {$jail})\n";
			return 0;
		}

		echo "Unknown action: {$action}\n";
		return 1;
	}
}
