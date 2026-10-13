<?php

namespace XcVm\Module\Firewall;

use XcVm\Cli\CommandInterface;

/**
 * FirewallManageCommand — Administrative CLI tool for Firewall & Fail2ban.
 *
 * Usage:
 *   php console.php firewall status
 *   php console.php firewall install
 *   php console.php firewall deploy
 *   php console.php firewall start|stop|restart|reload
 *   php console.php firewall ban <ip> [jail]
 *   php console.php firewall unban <ip> [jail]
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallManageCommand implements CommandInterface {

	public function getName(): string {
		return 'firewall';
	}

	public function getDescription(): string {
		return 'Manage Fail2ban firewall service, jails, and bans';
	}

	public function execute(array $rArgs): int {
		$sub = $rArgs[0] ?? 'status';

		switch ($sub) {
			case 'status':
				$status = FirewallService::getJailsStatus();
				echo "=== XC_VM Fail2ban Status ===\n";
				echo "Installed: " . ($status['installed'] ? 'Yes' : 'No') . "\n";
				echo "Running:   " . ($status['running'] ? 'ACTIVE (Running)' : 'INACTIVE (Stopped)') . "\n";
				echo "Total Banned IPs: " . $status['total_banned'] . "\n\n";

				if (!empty($status['jails'])) {
					echo sprintf("%-15s | %-8s | %-12s | %s\n", "Jail", "Failed", "Banned", "Banned IPs");
					echo str_repeat("-", 60) . "\n";
					foreach ($status['jails'] as $jName => $jData) {
						$ips = implode(', ', array_slice($jData['banned_ips'] ?? [], 0, 5));
						if (count($jData['banned_ips'] ?? []) > 5) {
							$ips .= '... (+' . (count($jData['banned_ips']) - 5) . ' more)';
						}
						echo sprintf(
							"%-15s | %-8d | %-12d | %s\n",
							$jName,
							$jData['currently_failed'] ?? 0,
							$jData['currently_banned'] ?? 0,
							$ips ?: 'none'
						);
					}
				}
				return 0;

			case 'install':
				echo "Starting Fail2ban installation & initial configuration...\n";
				$res = FirewallService::installPackage();
				echo $res['message'] . "\n";
				return $res['success'] ? 0 : 1;

			case 'deploy':
				echo "Deploying Fail2ban configurations and jail rules...\n";
				FirewallService::deployConfigs();
				FirewallService::reload();
				echo "Configuration deployed and service reloaded.\n";
				return 0;

			case 'reset-rules':
				echo "Resetting default rules to factory settings...\n";
				FirewallService::resetDefaultRules();
				echo "Default rules reset and deployed successfully.\n";
				return 0;


			case 'start':
				echo FirewallService::start() ? "Fail2ban started.\n" : "Failed to start Fail2ban.\n";
				return 0;

			case 'stop':
				echo FirewallService::stop() ? "Fail2ban stopped.\n" : "Failed to stop Fail2ban.\n";
				return 0;

			case 'restart':
				echo FirewallService::restart() ? "Fail2ban restarted.\n" : "Failed to restart Fail2ban.\n";
				return 0;

			case 'reload':
				echo FirewallService::reload() ? "Fail2ban reloaded.\n" : "Failed to reload Fail2ban.\n";
				return 0;

			case 'ban':
				$ip = $rArgs[1] ?? '';
				$jail = $rArgs[2] ?? 'xcvm-panel';
				if (!filter_var($ip, FILTER_VALIDATE_IP)) {
					echo "Error: Invalid IP address: {$ip}\n";
					return 1;
				}
				FirewallService::banIp($ip, $jail, 'CLI ban');
				echo "Banned {$ip} in {$jail}.\n";
				return 0;

			case 'unban':
				$ip = $rArgs[1] ?? '';
				$jail = $rArgs[2] ?? null;
				if (!filter_var($ip, FILTER_VALIDATE_IP)) {
					echo "Error: Invalid IP address: {$ip}\n";
					return 1;
				}
				FirewallService::unbanIp($ip, $jail);
				echo "Unbanned {$ip}.\n";
				return 0;

			default:
				echo "Unknown subcommand: {$sub}\n";
				echo "Available subcommands: status, install, deploy, start, stop, restart, reload, ban, unban\n";
				return 1;
		}
	}
}
