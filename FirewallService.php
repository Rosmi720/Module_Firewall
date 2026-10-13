<?php

namespace XcVm\Module\Firewall;

if (!defined('XC_VM_FIREWALL_AUTOLOADER_REGISTERED')) {
	define('XC_VM_FIREWALL_AUTOLOADER_REGISTERED', true);
	spl_autoload_register(static function (string $class): void {
		if (str_starts_with($class, 'XcVm\\Module\\Firewall\\')) {
			$rel = substr($class, strlen('XcVm\\Module\\Firewall\\'));
			$file = __DIR__ . '/' . str_replace('\\', '/', $rel) . '.php';
			if (is_file($file)) {
				require_once $file;
			}
		}
	});
}

use XcVm\Core\Cluster\BlocklistChanges;
use XcVm\Domain\Server\ServerRepository;
use XcVm\Infrastructure\Database\DatabaseAware;

/**
 * FirewallService — Core management service for Fail2ban & Firewall in XC_VM.
 *
 * Handles:
 * - Fail2ban service lifecycle (status, install, start, stop, restart, reload)
 * - Jails and Filters configuration generation
 * - IP Ban and Unban operations via fail2ban-client
 * - Two-way sync with XC_VM's `blocked_ips` table and Cluster LB propagation
 * - Audit logs and security event logging
 *
 * @package XC_VM_Module_Firewall
 * @author  Antigravity
 * @license AGPL-3.0
 */
class FirewallService {
	use DatabaseAware;

	public const CONFIG_DIR       = '/etc/fail2ban';
	public const JAIL_CONFIG      = '/etc/fail2ban/jail.d/xcvm.local';
	public const FILTER_PANEL    = '/etc/fail2ban/filter.d/xcvm-panel.conf';
	public const FILTER_STREAM   = '/etc/fail2ban/filter.d/xcvm-stream.conf';
	public const FILTER_FLOOD    = '/etc/fail2ban/filter.d/xcvm-flood.conf';
	public const ACTION_SYNC     = '/etc/fail2ban/action.d/xcvm-sync.conf';
	public const LOG_DIR          = '/var/log/xcvm';
	public const SECURITY_LOG     = '/var/log/xcvm/security.log';
	public const FAIL2BAN_LOG    = '/var/log/fail2ban.log';

	public const SUPPORTED_JAILS = ['sshd', 'xcvm-panel', 'xcvm-stream', 'xcvm-flood', 'xcvm-bots', 'xcvm-portscan'];

	// ───────────────────────────────────────────────────────────
	//  Service Lifecycle & Diagnostics
	// ───────────────────────────────────────────────────────────

	/**
	 * Check if Fail2ban is installed on the operating system.
	 */
	public static function isInstalled(): bool {
		$output = [];
		$exitCode = 1;
		@exec('which fail2ban-client 2>/dev/null', $output, $exitCode);
		return $exitCode === 0 && !empty($output);
	}

	/**
	 * Check if the Fail2ban service is currently active and running.
	 */
	public static function isRunning(): bool {
		if (!self::isInstalled()) {
			return false;
		}
		$output = [];
		$exitCode = 1;
		@exec('systemctl is-active fail2ban 2>/dev/null', $output, $exitCode);
		if ($exitCode === 0 && isset($output[0]) && trim($output[0]) === 'active') {
			return true;
		}

		// Fallback check via ping
		$pingOut = [];
		$pingCode = 1;
		@exec('sudo -n fail2ban-client ping 2>/dev/null', $pingOut, $pingCode);
		return $pingCode === 0 && isset($pingOut[0]) && stripos($pingOut[0], 'pong') !== false;
	}

	/**
	 * Install Fail2ban package and deploy initial configurations.
	 *
	 * @return array{success: bool, message: string}
	 */
	public static function installPackage(): array {
		if (self::isInstalled()) {
			self::deployConfigs();
			self::restart();
			return ['success' => true, 'message' => 'Fail2ban is already installed. Configuration re-deployed.'];
		}

		$out = [];
		$code = 0;
		@exec('export DEBIAN_FRONTEND=noninteractive; sudo -n apt-get update -y && sudo -n apt-get install -y fail2ban ipset 2>&1', $out, $code);

		if ($code !== 0 || !self::isInstalled()) {
			$msg = implode("\n", array_slice($out, -5));
			return ['success' => false, 'message' => 'Installation failed: ' . $msg];
		}

		self::deployConfigs();
		@exec('sudo -n systemctl enable fail2ban 2>/dev/null');
		self::restart();

		return ['success' => true, 'message' => 'Fail2ban successfully installed, configured and started.'];
	}

	/**
	 * Start the Fail2ban system service.
	 */
	public static function start(): bool {
		$code = 1;
		@exec('sudo -n systemctl start fail2ban 2>/dev/null', $out, $code);
		return $code === 0;
	}

	/**
	 * Stop the Fail2ban system service.
	 */
	public static function stop(): bool {
		$code = 1;
		@exec('sudo -n systemctl stop fail2ban 2>/dev/null', $out, $code);
		return $code === 0;
	}

	/**
	 * Restart the Fail2ban system service.
	 */
	public static function restart(): bool {
		$code = 1;
		@exec('sudo -n systemctl restart fail2ban 2>/dev/null', $out, $code);
		return $code === 0;
	}

	/**
	 * Reload Fail2ban configuration without dropping active bans.
	 */
	public static function reload(): bool {
		if (!self::isRunning()) {
			return self::start();
		}
		$code = 1;
		$out = [];
		@exec('sudo -n fail2ban-client reload 2>&1', $out, $code);
		if ($code === 0) {
			return true;
		}

		// Fallback: try systemctl reload
		$sysCode = 1;
		@exec('sudo -n systemctl reload fail2ban 2>/dev/null', $sysOut, $sysCode);
		if ($sysCode === 0) {
			return true;
		}

		// Secondary fallback: restart service
		return self::restart();
	}

	// ───────────────────────────────────────────────────────────
	//  Rules Management Engine (Default & Custom Rules)
	// ───────────────────────────────────────────────────────────

	/**
	 * Ensure database tables exist and populate initial default rules.
	 */
	public static function initTables(): void {
		$db = self::db();
		try {
			$db->query("CREATE TABLE IF NOT EXISTS `module_firewall_settings` (
				`key` VARCHAR(64) NOT NULL PRIMARY KEY,
				`value` TEXT NOT NULL,
				`updated_at` INT UNSIGNED NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

			$db->query("CREATE TABLE IF NOT EXISTS `module_firewall_history` (
				`id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
				`ip` VARCHAR(45) NOT NULL,
				`jail` VARCHAR(32) NOT NULL,
				`action` ENUM('BAN', 'UNBAN') NOT NULL,
				`reason` VARCHAR(255) NULL,
				`date` INT UNSIGNED NOT NULL,
				INDEX `idx_ip` (`ip`),
				INDEX `idx_date` (`date`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

			$db->query("CREATE TABLE IF NOT EXISTS `module_firewall_rules` (
				`id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
				`rule_key` VARCHAR(64) NOT NULL UNIQUE,
				`name` VARCHAR(128) NOT NULL,
				`category` ENUM('default', 'custom') NOT NULL DEFAULT 'custom',
				`enabled` TINYINT(1) NOT NULL DEFAULT 1,
				`port` VARCHAR(128) NOT NULL DEFAULT 'all',
				`protocol` VARCHAR(16) NOT NULL DEFAULT 'tcp',
				`filter_regex` TEXT NULL,
				`log_path` VARCHAR(255) NULL,
				`maxretry` INT UNSIGNED NOT NULL DEFAULT 5,
				`findtime` INT UNSIGNED NOT NULL DEFAULT 600,
				`bantime` INT UNSIGNED NOT NULL DEFAULT 3600,
				`action_type` VARCHAR(64) NOT NULL DEFAULT 'iptables-multiport',
				`description` TEXT NULL,
				`created_at` INT UNSIGNED NOT NULL,
				`updated_at` INT UNSIGNED NOT NULL,
				INDEX `idx_category` (`category`),
				INDEX `idx_enabled` (`enabled`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

			// Check if rules table has rows
			$check = $db->query("SELECT COUNT(*) AS `cnt` FROM `module_firewall_rules`");
			if ($check) {
				$row = $db->get_row();
				if ((int) ($row['cnt'] ?? 0) === 0) {
					self::seedDefaultRules();
				}
			}
		} catch (\Throwable $e) {
			error_log('FirewallService::initTables error: ' . $e->getMessage());
		}
	}

	/**
	 * Default project core rules definitions.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function getDefaultRulesDefinitions(): array {
		return [
			[
				'rule_key'     => 'sshd',
				'name'         => 'SSH Brute-Force Shield',
				'category'     => 'default',
				'enabled'      => 1,
				'port'         => 'ssh,22',
				'protocol'     => 'tcp',
				'filter_regex' => null,
				'log_path'     => '/var/log/auth.log',
				'maxretry'     => 5,
				'findtime'     => 600,
				'bantime'      => 86400,
				'action_type'  => 'iptables-multiport',
				'description'  => 'Monitors SSH service and aggressively bans brute-force authentication attempts.',
			],
			[
				'rule_key'     => 'xcvm-panel',
				'name'         => 'Panel Admin & Reseller Protection',
				'category'     => 'default',
				'enabled'      => 1,
				'port'         => 'http,https,80,443',
				'protocol'     => 'tcp',
				'filter_regex' => '^.*\[xcvm-panel\]\s+<HOST>\s+-\s+Failed login.*$',
				'log_path'     => '/var/log/xcvm/security.log',
				'maxretry'     => 5,
				'findtime'     => 600,
				'bantime'      => 7200,
				'action_type'  => 'iptables-multiport',
				'description'  => 'Protects Admin and Reseller login endpoints from credential stuffing and dictionary attacks.',
			],
			[
				'rule_key'     => 'xcvm-stream',
				'name'         => 'Stream API & Player Token Guard',
				'category'     => 'default',
				'enabled'      => 1,
				'port'         => 'http,https,80,443,8880,31210',
				'protocol'     => 'tcp',
				'filter_regex' => '^.*\[xcvm-stream\]\s+<HOST>\s+-\s+(?:Invalid credentials|Invalid stream ID|Blocked user agent).*$',
				'log_path'     => '/var/log/xcvm/security.log',
				'maxretry'     => 10,
				'findtime'     => 300,
				'bantime'      => 3600,
				'action_type'  => 'iptables-multiport',
				'description'  => 'Blocks unauthorized stream scrapers, expired playlist loopers and token brute-forcers.',
			],
			[
				'rule_key'     => 'xcvm-flood',
				'name'         => 'Connection Flood & Rate Mitigator',
				'category'     => 'default',
				'enabled'      => 1,
				'port'         => 'http,https,80,443',
				'protocol'     => 'tcp',
				'filter_regex' => '^.*\[xcvm-flood\]\s+<HOST>\s+-\s+Request flood detected.*$',
				'log_path'     => '/var/log/xcvm/security.log',
				'maxretry'     => 120,
				'findtime'     => 60,
				'bantime'      => 1800,
				'action_type'  => 'iptables-multiport',
				'description'  => 'Mitigates HTTP request flooding, Layer-7 connection floods and high-frequency hammering.',
			],
			[
				'rule_key'     => 'xcvm-bots',
				'name'         => 'Bad Bots & Exploit Scanner Filter',
				'category'     => 'default',
				'enabled'      => 1,
				'port'         => 'http,https,80,443',
				'protocol'     => 'tcp',
				'filter_regex' => '^.*\[xcvm-bots\]\s+<HOST>\s+-\s+(?:Vulnerability probe|Exploit scanner|Blocked scraper).*$',
				'log_path'     => '/var/log/xcvm/security.log',
				'maxretry'     => 3,
				'findtime'     => 300,
				'bantime'      => 43200,
				'action_type'  => 'iptables-multiport',
				'description'  => 'Instantly bans automated exploit probes, SQLi scanners, and known malicious scraper bots.',
			],
			[
				'rule_key'     => 'xcvm-portscan',
				'name'         => 'Port Scan & Reconnaissance Blocker',
				'category'     => 'default',
				'enabled'      => 0,
				'port'         => 'all',
				'protocol'     => 'all',
				'filter_regex' => '^.*\[xcvm-portscan\]\s+<HOST>\s+-\s+Unsolicited port probe.*$',
				'log_path'     => '/var/log/xcvm/security.log',
				'maxretry'     => 2,
				'findtime'     => 120,
				'bantime'      => 86400,
				'action_type'  => 'iptables-allports',
				'description'  => 'Detects and blocks network reconnaissance, unauthorized port probing and hostile scans.',
			],
		];
	}

	/**
	 * Seed standard default rules into module_firewall_rules table.
	 */
	public static function seedDefaultRules(): void {
		$db = self::db();
		$defaults = self::getDefaultRulesDefinitions();
		$now = time();

		foreach ($defaults as $rule) {
			try {
				$db->query(
					'INSERT INTO `module_firewall_rules`
					(`rule_key`, `name`, `category`, `enabled`, `port`, `protocol`, `filter_regex`, `log_path`, `maxretry`, `findtime`, `bantime`, `action_type`, `description`, `created_at`, `updated_at`)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					ON DUPLICATE KEY UPDATE
					`name` = VALUES(`name`),
					`port` = VALUES(`port`),
					`protocol` = VALUES(`protocol`),
					`filter_regex` = VALUES(`filter_regex`),
					`log_path` = VALUES(`log_path`),
					`description` = VALUES(`description`),
					`updated_at` = VALUES(`updated_at`)',
					$rule['rule_key'],
					$rule['name'],
					'default',
					$rule['enabled'] ? 1 : 0,
					$rule['port'],
					$rule['protocol'],
					$rule['filter_regex'],
					$rule['log_path'],
					(int) $rule['maxretry'],
					(int) $rule['findtime'],
					(int) $rule['bantime'],
					$rule['action_type'],
					$rule['description'],
					$now,
					$now
				);
			} catch (\Throwable $e) {
				error_log('FirewallService::seedDefaultRules: ' . $e->getMessage());
			}
		}
	}

	/**
	 * Retrieve all firewall and fail2ban rules.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function getAllRules(): array {
		self::initTables();
		$db = self::db();
		try {
			$res = $db->query('SELECT * FROM `module_firewall_rules` ORDER BY `category` ASC, `id` ASC');
			if ($res) {
				$rows = $db->get_rows() ?: [];
				if (!empty($rows)) {
					return $rows;
				}
			}
		} catch (\Throwable) {
		}

		return self::getDefaultRulesDefinitions();
	}

	/**
	 * Retrieve a single rule by rule_key.
	 *
	 * @param string|null $ruleKey
	 * @return array<string, mixed>|null
	 */
	public static function getRule(?string $ruleKey): ?array {
		if ($ruleKey === null || trim($ruleKey) === '') {
			return null;
		}
		$ruleKey = trim($ruleKey);
		self::initTables();
		$db = self::db();
		try {
			$res = $db->query('SELECT * FROM `module_firewall_rules` WHERE `rule_key` = ? LIMIT 1', $ruleKey);
			if ($res) {
				$row = $db->get_row();
				if (!empty($row)) {
					return $row;
				}
			}
		} catch (\Throwable) {
		}

		foreach (self::getDefaultRulesDefinitions() as $d) {
			if ($d['rule_key'] === $ruleKey) {
				return $d;
			}
		}

		return null;
	}

	/**
	 * Save (create or update) a firewall rule.
	 *
	 * @param array<string, mixed>|null $data
	 * @return array{success: bool, message: string}
	 */
	public static function saveRule(?array $data = null): array {
		self::initTables();
		$data = $data ?? [];
		$db = self::db();

		$ruleKey = strtolower(trim((string) ($data['rule_key'] ?? '')));
		$ruleKey = (string) preg_replace('/[^a-z0-9_-]/', '', $ruleKey);

		if ($ruleKey === '') {
			return ['success' => false, 'message' => 'Rule key is required and must contain alphanumeric characters, underscores or dashes only.'];
		}

		$name = trim((string) ($data['name'] ?? $ruleKey));
		if ($name === '') {
			$name = ucfirst($ruleKey);
		}

		$category = ($data['category'] ?? 'custom') === 'default' ? 'default' : 'custom';
		$enabled = !empty($data['enabled']) ? 1 : 0;
		$port = trim((string) ($data['port'] ?? '80,443'));
		if ($port === '') {
			$port = 'all';
		}
		$protocol = in_array(strtolower(trim((string) ($data['protocol'] ?? 'tcp'))), ['tcp', 'udp', 'all'], true) ? strtolower(trim((string) ($data['protocol'] ?? 'tcp'))) : 'tcp';
		$filterRegex = isset($data['filter_regex']) ? trim((string) $data['filter_regex']) : null;
		$logPath = trim((string) ($data['log_path'] ?? '/var/log/xcvm/security.log'));
		if ($logPath === '') {
			$logPath = '/var/log/xcvm/security.log';
		}
		$maxretry = max(1, min(1000, (int) ($data['maxretry'] ?? 5)));
		$findtime = max(10, min(86400 * 7, (int) ($data['findtime'] ?? 600)));
		$bantime = max(30, min(86400 * 365, (int) ($data['bantime'] ?? 3600)));
		$actionType = trim((string) ($data['action_type'] ?? 'iptables-multiport'));
		if (!in_array($actionType, ['iptables-multiport', 'iptables-allports', 'nftables'], true)) {
			$actionType = ($port === 'all') ? 'iptables-allports' : 'iptables-multiport';
		}
		$description = trim((string) ($data['description'] ?? ''));

		$now = time();

		try {
			$existing = self::getRule($ruleKey);
			if ($existing) {
				// Update
				$db->query(
					'UPDATE `module_firewall_rules` SET
					`name` = ?,
					`enabled` = ?,
					`port` = ?,
					`protocol` = ?,
					`filter_regex` = ?,
					`log_path` = ?,
					`maxretry` = ?,
					`findtime` = ?,
					`bantime` = ?,
					`action_type` = ?,
					`description` = ?,
					`updated_at` = ?
					WHERE `rule_key` = ?',
					$name,
					$enabled,
					$port,
					$protocol,
					$filterRegex ?: null,
					$logPath,
					$maxretry,
					$findtime,
					$bantime,
					$actionType,
					$description,
					$now,
					$ruleKey
				);
			} else {
				// Insert new custom rule
				$db->query(
					'INSERT INTO `module_firewall_rules`
					(`rule_key`, `name`, `category`, `enabled`, `port`, `protocol`, `filter_regex`, `log_path`, `maxretry`, `findtime`, `bantime`, `action_type`, `description`, `created_at`, `updated_at`)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
					$ruleKey,
					$name,
					$category,
					$enabled,
					$port,
					$protocol,
					$filterRegex ?: null,
					$logPath,
					$maxretry,
					$findtime,
					$bantime,
					$actionType,
					$description,
					$now,
					$now
				);
			}

			// Deploy configurations and reload
			self::deployConfigs();
			if (self::isRunning()) {
				self::reload();
			}

			return ['success' => true, 'message' => "Rule '{$name}' saved and applied successfully."];
		} catch (\Throwable $e) {
			return ['success' => false, 'message' => 'Database error saving rule: ' . $e->getMessage()];
		}
	}

	/**
	 * Delete a custom firewall rule.
	 *
	 * @param string|null $ruleKey
	 * @return array{success: bool, message: string}
	 */
	public static function deleteRule(?string $ruleKey): array {
		if ($ruleKey === null || trim($ruleKey) === '') {
			return ['success' => false, 'message' => 'Rule key is required.'];
		}
		$ruleKey = trim($ruleKey);

		$rule = self::getRule($ruleKey);
		if (!$rule) {
			return ['success' => false, 'message' => 'Rule not found.'];
		}

		if (($rule['category'] ?? '') === 'default') {
			return ['success' => false, 'message' => 'Default core project rules cannot be deleted. You can disable them instead.'];
		}

		$db = self::db();
		try {
			$db->query('DELETE FROM `module_firewall_rules` WHERE `rule_key` = ?', $ruleKey);

			// Delete generated filter file if exists
			$filterFile = self::CONFIG_DIR . '/filter.d/' . $ruleKey . '.conf';
			if (file_exists($filterFile)) {
				@unlink($filterFile);
			}

			self::deployConfigs();
			if (self::isRunning()) {
				self::reload();
			}

			return ['success' => true, 'message' => "Custom rule '{$ruleKey}' deleted successfully."];
		} catch (\Throwable $e) {
			return ['success' => false, 'message' => 'Error deleting rule: ' . $e->getMessage()];
		}
	}

	/**
	 * Toggle active status of a rule (enable or disable).
	 *
	 * @param string|null $ruleKey
	 * @param bool|null   $enabled
	 * @return array{success: bool, message: string}
	 */
	public static function toggleRule(?string $ruleKey, ?bool $enabled = null): array {
		if ($ruleKey === null || trim($ruleKey) === '') {
			return ['success' => false, 'message' => 'Rule key is required.'];
		}
		$ruleKey = trim($ruleKey);

		$rule = self::getRule($ruleKey);
		if (!$rule) {
			return ['success' => false, 'message' => 'Rule not found.'];
		}

		$newStatus = ($enabled !== null) ? ($enabled ? 1 : 0) : (((int) ($rule['enabled'] ?? 1)) === 1 ? 0 : 1);
		$db = self::db();

		try {
			$db->query('UPDATE `module_firewall_rules` SET `enabled` = ?, `updated_at` = ? WHERE `rule_key` = ?', $newStatus, time(), $ruleKey);

			self::deployConfigs();
			if (self::isRunning()) {
				self::reload();
			}

			$statusWord = $newStatus === 1 ? 'enabled' : 'disabled';
			return ['success' => true, 'message' => "Rule '{$ruleKey}' is now {$statusWord}."];
		} catch (\Throwable $e) {
			return ['success' => false, 'message' => 'Error toggling rule: ' . $e->getMessage()];
		}
	}

	/**
	 * Reset all default core rules to factory settings.
	 */
	public static function resetDefaultRules(): bool {
		self::initTables();
		$db = self::db();
		try {
			$db->query("DELETE FROM `module_firewall_rules` WHERE `category` = 'default'");
		} catch (\Throwable) {
		}
		self::seedDefaultRules();
		self::deployConfigs();
		if (self::isRunning()) {
			self::reload();
		}
		return true;
	}


	/**
	 * Validate and test a regex against a sample log line or text.
	 *
	 * @param string|null $regex
	 * @param string|null $sampleLog
	 * @return array{success: bool, matches: int, message: string}
	 */
	public static function testRegex(?string $regex, ?string $sampleLog): array {
		$regex = trim((string) $regex);
		$sampleLog = trim((string) $sampleLog);

		if ($regex === '') {
			return ['success' => false, 'matches' => 0, 'message' => 'Regular expression cannot be empty.'];
		}
		if ($sampleLog === '') {
			return ['success' => false, 'matches' => 0, 'message' => 'Sample log line is required to test against.'];
		}

		// Convert Fail2ban <HOST> placeholder to PHP PCRE equivalent for syntax and match test
		$phpRegex = str_replace('<HOST>', '(?P<host>[a-fA-F0-9:.]+)', $regex);
		$pattern = '#' . str_replace('#', '\#', $phpRegex) . '#m';

		$matchCount = 0;
		$matches = [];
		$isValid = @preg_match_all($pattern, $sampleLog, $matches);

		if ($isValid === false) {
			$error = error_get_last();
			return [
				'success' => false,
				'matches' => 0,
				'message' => 'Invalid Regex syntax: ' . ($error['message'] ?? 'PCRE compilation error'),
			];
		}

		$matchCount = count($matches[0] ?? []);
		if ($matchCount > 0) {
			$firstHost = $matches['host'][0] ?? 'N/A';
			return [
				'success' => true,
				'matches' => $matchCount,
				'message' => "Success! Regex matched {$matchCount} line(s). Extracted IP/Host: {$firstHost}",
			];
		}

		return [
			'success' => true,
			'matches' => 0,
			'message' => 'Valid regex syntax, but 0 matches were found in the provided sample.',
		];
	}

	// ───────────────────────────────────────────────────────────
	//  Settings & Config Generator
	// ───────────────────────────────────────────────────────────

	/**
	 * Default settings for the Firewall & Fail2ban module.
	 *
	 * @return array<string, mixed>
	 */
	public static function getDefaultSettings(): array {
		$ownIPs = self::detectWhitelistedIPs();

		return [
			'preset'    => 'balanced',
			'ignoreip'  => implode(' ', $ownIPs),
			'sync_to_db' => true,
			'jails'     => [
				'sshd' => [
					'enabled'  => true,
					'port'     => 'ssh,22',
					'maxretry' => 5,
					'findtime' => 600,
					'bantime'  => 86400,
				],
				'xcvm-panel' => [
					'enabled'  => true,
					'port'     => 'http,https,80,443',
					'maxretry' => 5,
					'findtime' => 600,
					'bantime'  => 7200,
				],
				'xcvm-stream' => [
					'enabled'  => true,
					'port'     => 'http,https,80,443,8880,31210',
					'maxretry' => 10,
					'findtime' => 300,
					'bantime'  => 3600,
				],
				'xcvm-flood' => [
					'enabled'  => true,
					'port'     => 'http,https,80,443',
					'maxretry' => 120,
					'findtime' => 60,
					'bantime'  => 1800,
				],
				'xcvm-bots' => [
					'enabled'  => true,
					'port'     => 'http,https,80,443',
					'maxretry' => 3,
					'findtime' => 300,
					'bantime'  => 43200,
				],
				'xcvm-portscan' => [
					'enabled'  => false,
					'port'     => 'all',
					'maxretry' => 2,
					'findtime' => 120,
					'bantime'  => 86400,
				],
			],
		];
	}


	/**
	 * Automatically detect IPs that should be whitelisted (own server IP, LB IPs, loopback).
	 *
	 * @return list<string>
	 */
	public static function detectWhitelistedIPs(): array {
		$ips = ['127.0.0.1/8', '::1'];

		// Add current server main IP
		if (isset($_SERVER['SERVER_ADDR']) && filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP)) {
			$ips[] = $_SERVER['SERVER_ADDR'];
		}

		// Add IPs of all cluster servers (Load Balancers)
		if (class_exists(ServerRepository::class)) {
			try {
				$servers = ServerRepository::getAll();
				foreach ($servers as $srv) {
					if (!empty($srv['server_ip']) && filter_var($srv['server_ip'], FILTER_VALIDATE_IP)) {
						$ips[] = $srv['server_ip'];
					}
					if (!empty($srv['private_ip']) && filter_var($srv['private_ip'], FILTER_VALIDATE_IP)) {
						$ips[] = $srv['private_ip'];
					}
				}
			} catch (\Throwable) {
				// ServerRepository not available in this context
			}
		}

		return array_values(array_unique(array_filter($ips)));
	}

	/**
	 * Retrieve saved module settings from database or fallback to defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function getSettings(): array {
		$db = self::db();
		$settings = self::getDefaultSettings();

		try {
			$res = $db->query('SELECT `key`, `value` FROM `module_firewall_settings`');
			if ($res) {
				$rows = $db->get_rows();
				foreach ($rows as $row) {
					$val = json_decode((string) $row['value'], true);
					$settings[$row['key']] = $val !== null ? $val : $row['value'];
				}
			}
		} catch (\Throwable) {
			// Database table might not be migrated yet
		}

		return $settings;
	}

	/**
	 * Save updated settings and re-deploy config files.
	 *
	 * @param array<string, mixed>|null $data
	 */
	public static function saveSettings(?array $data = null): bool {
		$data = $data ?? [];
		$db = self::db();
		$current = self::getSettings();

		if (isset($data['preset'])) {
			$current['preset'] = (string) $data['preset'];
		}
		if (isset($data['sync_to_db'])) {
			$current['sync_to_db'] = (bool) $data['sync_to_db'];
		}
		if (isset($data['ignoreip'])) {
			$current['ignoreip'] = trim((string) $data['ignoreip']);
		}

		if (isset($data['jails']) && is_array($data['jails'])) {
			foreach ($data['jails'] as $jailName => $jConfig) {
				if (in_array($jailName, self::SUPPORTED_JAILS, true) && is_array($jConfig)) {
					$current['jails'][$jailName] = [
						'enabled'  => !empty($jConfig['enabled']),
						'port'     => (string) ($jConfig['port'] ?? $current['jails'][$jailName]['port']),
						'maxretry' => max(1, (int) ($jConfig['maxretry'] ?? 5)),
						'findtime' => max(10, (int) ($jConfig['findtime'] ?? 600)),
						'bantime'  => max(30, (int) ($jConfig['bantime'] ?? 3600)),
					];
				}
			}
		}

		// Persist each key
		$now = time();
		foreach ($current as $k => $v) {
			$val = is_scalar($v) ? (string) $v : json_encode($v);
			$db->query(
				'INSERT INTO `module_firewall_settings` (`key`, `value`, `updated_at`) VALUES (?, ?, ?)
				 ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `updated_at` = VALUES(`updated_at`)',
				$k,
				$val,
				$now
			);
		}

		// Deploy new configuration files and reload
		self::deployConfigs();
		if (self::isRunning()) {
			self::reload();
		}

		return true;
	}

	/**
	 * Write all Fail2ban filters, actions, and jail configurations to disk.
	 */
	public static function deployConfigs(): bool {
		if (!is_dir(self::LOG_DIR)) {
			@mkdir(self::LOG_DIR, 0755, true);
		}
		if (!file_exists(self::SECURITY_LOG)) {
			@touch(self::SECURITY_LOG);
			@chmod(self::SECURITY_LOG, 0666);
		}

		$settings = self::getSettings();
		$ignoreip = !empty($settings['ignoreip']) ? $settings['ignoreip'] : implode(' ', self::detectWhitelistedIPs());

		// 1. Action: xcvm-sync (Call console command to sync with blocked_ips)
		$phpBin = defined('PHP_BIN') ? PHP_BIN : '/usr/bin/php';
		$console = defined('MAIN_HOME') ? MAIN_HOME . 'console.php' : '/home/xc_vm/console.php';

		$actionSync = <<<INI
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = {$phpBin} {$console} firewall:sync ban <ip> <name>
actionunban = {$phpBin} {$console} firewall:sync unban <ip> <name>
INI;

		@file_put_contents(self::ACTION_SYNC, $actionSync);

		// 2. Load all rules (default and custom)
		$rules = self::getAllRules();

		// Ensure filter.d directory exists
		$filterDir = self::CONFIG_DIR . '/filter.d';
		if (!is_dir($filterDir)) {
			@mkdir($filterDir, 0755, true);
		}

		// 3. Generate filters for all rules with filter_regex
		foreach ($rules as $r) {
			$ruleKey = (string) ($r['rule_key'] ?? '');
			$regex   = trim((string) ($r['filter_regex'] ?? ''));
			if ($regex !== '') {
				$regex = html_entity_decode($regex, ENT_QUOTES | ENT_HTML5, 'UTF-8');
				$regex = str_replace(['&lt;', '&gt;'], ['<', '>'], $regex);
			}

			if ($ruleKey !== '' && $regex !== '') {
				$filterContent = <<<INI
[Definition]
failregex = {$regex}
ignoreregex =
INI;
				@file_put_contents($filterDir . '/' . $ruleKey . '.conf', $filterContent);
			}
		}


		// 4. Build dynamic /etc/fail2ban/jail.d/xcvm.local
		$jailConfig = <<<INI
[DEFAULT]
ignoreip = {$ignoreip}
bantime  = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport
banaction_allports = iptables-allports

INI;

		foreach ($rules as $r) {
			$ruleKey = (string) ($r['rule_key'] ?? '');
			if ($ruleKey === '') {
				continue;
			}

			$enabled = !empty($r['enabled']) ? 'true' : 'false';
			$port = trim((string) ($r['port'] ?? '80,443'));
			if ($port === '') {
				$port = 'all';
			}
			$protocol = in_array(strtolower(trim((string) ($r['protocol'] ?? 'tcp'))), ['tcp', 'udp', 'all'], true) ? strtolower(trim((string) ($r['protocol'] ?? 'tcp'))) : 'tcp';
			$maxretry = max(1, (int) ($r['maxretry'] ?? 5));
			$findtime = max(10, (int) ($r['findtime'] ?? 600));
			$bantime = max(30, (int) ($r['bantime'] ?? 3600));
			$actionType = (string) ($r['action_type'] ?? 'iptables-multiport');
			$logPath = trim((string) ($r['log_path'] ?? '/var/log/xcvm/security.log'));
			if ($logPath === '') {
				$logPath = '/var/log/xcvm/security.log';
			}

			if ($ruleKey === 'sshd') {
				$jailConfig .= <<<INI
[sshd]
enabled  = {$enabled}
port     = {$port}
maxretry = {$maxretry}
findtime = {$findtime}
bantime  = {$bantime}
action   = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="{$protocol}"]
           xcvm-sync[name=%(__name__)s]

INI;
			} elseif ($port === 'all' || $actionType === 'iptables-allports') {
				$jailConfig .= <<<INI
[{$ruleKey}]
enabled  = {$enabled}
filter   = {$ruleKey}
logpath  = {$logPath}
maxretry = {$maxretry}
findtime = {$findtime}
bantime  = {$bantime}
action   = %(banaction_allports)s[name=%(__name__)s, protocol="{$protocol}"]
           xcvm-sync[name=%(__name__)s]

INI;
			} else {
				$jailConfig .= <<<INI
[{$ruleKey}]
enabled  = {$enabled}
filter   = {$ruleKey}
logpath  = {$logPath}
port     = {$port}
maxretry = {$maxretry}
findtime = {$findtime}
bantime  = {$bantime}
action   = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="{$protocol}"]
           xcvm-sync[name=%(__name__)s]

INI;
			}
		}

		@file_put_contents(self::JAIL_CONFIG, $jailConfig);

		return true;
	}

	// ───────────────────────────────────────────────────────────
	//  Jail Inspection & Banned IPs
	// ───────────────────────────────────────────────────────────

	/**
	 * Get status overview and banned IP list for all active Jails.
	 *
	 * @return array{running: bool, installed: bool, total_banned: int, jails: array<string, array<string, mixed>>}
	 */
	public static function getJailsStatus(): array {
		$installed = self::isInstalled();
		$running   = self::isRunning();

		$result = [
			'installed'    => $installed,
			'running'      => $running,
			'total_banned' => 0,
			'jails'        => [],
		];

		if (!$installed || !$running) {
			return $result;
		}

		$statusOut = [];
		@exec('sudo -n fail2ban-client status 2>/dev/null', $statusOut);
		$activeJails = [];

		foreach ($statusOut as $line) {
			if (stripos($line, 'Jail list:') !== false) {
				$parts = explode(':', $line, 2);
				if (isset($parts[1])) {
					$names = explode(',', trim($parts[1]));
					foreach ($names as $n) {
						$trimmed = trim($n);
						if ($trimmed !== '') {
							$activeJails[] = $trimmed;
						}
					}
				}
			}
		}

		$totalBannedCount = 0;
		foreach ($activeJails as $jail) {
			$jailOut = [];
			@exec('sudo -n fail2ban-client status ' . escapeshellarg($jail) . ' 2>/dev/null', $jailOut);

			$currentlyFailed = 0;
			$totalFailed     = 0;
			$currentlyBanned = 0;
			$totalBanned     = 0;
			$bannedIPList    = [];

			foreach ($jailOut as $jLine) {
				if (stripos($jLine, 'Currently failed:') !== false) {
					$currentlyFailed = (int) preg_replace('/[^0-9]/', '', $jLine);
				} elseif (stripos($jLine, 'Total failed:') !== false) {
					$totalFailed = (int) preg_replace('/[^0-9]/', '', $jLine);
				} elseif (stripos($jLine, 'Currently banned:') !== false) {
					$currentlyBanned = (int) preg_replace('/[^0-9]/', '', $jLine);
				} elseif (stripos($jLine, 'Total banned:') !== false) {
					$totalBanned = (int) preg_replace('/[^0-9]/', '', $jLine);
				} elseif (stripos($jLine, 'Banned IP list:') !== false) {
					$bParts = explode(':', $jLine, 2);
					if (isset($bParts[1])) {
						$ips = preg_split('/\s+/', trim($bParts[1]));
						if (is_array($ips)) {
							foreach ($ips as $ip) {
								$ip = trim($ip);
								if (filter_var($ip, FILTER_VALIDATE_IP)) {
									$bannedIPList[] = $ip;
								}
							}
						}
					}
				}
			}

			$totalBannedCount += $currentlyBanned;
			$result['jails'][$jail] = [
				'currently_failed' => $currentlyFailed,
				'total_failed'     => $totalFailed,
				'currently_banned' => $currentlyBanned,
				'total_banned'     => $totalBanned,
				'banned_ips'       => $bannedIPList,
			];
		}

		$result['total_banned'] = $totalBannedCount;
		return $result;
	}

	// ───────────────────────────────────────────────────────────
	//  Ban & Unban Operations
	// ───────────────────────────────────────────────────────────

	/**
	 * Unban an IP address from Fail2ban and optionally remove from blocked_ips.
	 *
	 * @param string|null $ip   The IP address to unban.
	 * @param string|null $jail Specific jail name or null for all.
	 * @return bool True if executed successfully.
	 */
	public static function unbanIp(?string $ip, ?string $jail = null): bool {
		$ip = trim((string) $ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return false;
		}

		$jails = ($jail !== null && $jail !== 'all') ? [$jail] : self::SUPPORTED_JAILS;
		$escapedIp = escapeshellarg($ip);

		foreach ($jails as $j) {
			$escapedJail = escapeshellarg($j);
			@exec("sudo -n fail2ban-client set {$escapedJail} unbanip {$escapedIp} 2>/dev/null");
		}

		// Also execute unban across any active jail via fail2ban-client unban
		@exec("sudo -n fail2ban-client unban {$escapedIp} 2>/dev/null");

		// Remove from blocked_ips if sync is enabled
		$db = self::db();
		try {
			$db->query('DELETE FROM `blocked_ips` WHERE `ip` = ?', $ip);
			BlocklistChanges::set('ip', [$ip], $db);

			// Log history
			$db->query(
				'INSERT INTO `module_firewall_history` (`ip`, `jail`, `action`, `reason`, `date`) VALUES (?, ?, ?, ?, ?)',
				$ip,
				$jail ?? 'all',
				'UNBAN',
				'Manual unban from Firewall panel',
				time()
			);
		} catch (\Throwable) {
		}

		return true;
	}

	/**
	 * Manually ban an IP address in a specific Jail and sync to blocked_ips.
	 *
	 * @param string|null $ip     The IP address to ban.
	 * @param string|null $jail   The target jail (defaults to xcvm-panel).
	 * @param string|null $reason Reason note for audit.
	 */
	public static function banIp(?string $ip, ?string $jail = 'xcvm-panel', ?string $reason = 'Manual ban'): bool {
		$ip = trim((string) $ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return false;
		}

		$jail = in_array($jail, self::SUPPORTED_JAILS, true) ? $jail : 'xcvm-panel';
		$escapedIp = escapeshellarg($ip);
		$escapedJail = escapeshellarg($jail);

		$code = 1;
		@exec("sudo -n fail2ban-client set {$escapedJail} banip {$escapedIp} 2>/dev/null", $out, $code);

		// Sync to database
		self::handleActionBan($ip, $jail, $reason);

		return $code === 0;
	}

	/**
	 * Callback handler invoked when Fail2ban bans an IP (via xcvm-sync action).
	 */
	public static function handleActionBan(?string $ip, ?string $jail = 'unknown', ?string $reason = null): void {
		$ip = trim((string) $ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return;
		}

		$db = self::db();
		$note = 'Fail2ban: ' . ($jail ?? 'custom') . ($reason ? ' (' . $reason . ')' : '');

		try {
			$db->query(
				'INSERT INTO `blocked_ips` (`ip`, `notes`, `date`) VALUES (?, ?, ?)
				 ON DUPLICATE KEY UPDATE `notes` = VALUES(`notes`), `date` = VALUES(`date`)',
				$ip,
				$note,
				time()
			);

			BlocklistChanges::set('ip', [$ip], $db);

			$db->query(
				'INSERT INTO `module_firewall_history` (`ip`, `jail`, `action`, `reason`, `date`) VALUES (?, ?, ?, ?, ?)',
				$ip,
				$jail ?? 'unknown',
				'BAN',
				$reason ?? 'Triggered by Fail2ban filter',
				time()
			);
		} catch (\Throwable) {
		}
	}

	/**
	 * Callback handler invoked when Fail2ban unbans an IP (via xcvm-sync action).
	 */
	public static function handleActionUnban(?string $ip, ?string $jail = 'unknown'): void {
		$ip = trim((string) $ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return;
		}

		$db = self::db();
		try {
			$db->query("DELETE FROM `blocked_ips` WHERE `ip` = ? AND `notes` LIKE 'Fail2ban:%'", $ip);
			BlocklistChanges::set('ip', [$ip], $db);

			$db->query(
				'INSERT INTO `module_firewall_history` (`ip`, `jail`, `action`, `reason`, `date`) VALUES (?, ?, ?, ?, ?)',
				$ip,
				$jail ?? 'unknown',
				'UNBAN',
				'Unbanned by Fail2ban timer',
				time()
			);
		} catch (\Throwable) {
		}
	}

	// ───────────────────────────────────────────────────────────
	//  Security Event Logger & Log Viewer
	// ───────────────────────────────────────────────────────────

	/**
	 * Record a security alert into /var/log/xcvm/security.log.
	 *
	 * Format:
	 * 2026-10-13 12:30:00 [xcvm-panel] 192.168.1.100 - Failed login for user 'admin'
	 *
	 * @param string|null $jailTag Jail identifier ('xcvm-panel', 'xcvm-stream', 'xcvm-flood')
	 * @param string|null $ip      Target IP address
	 * @param string|null $message Descriptive message
	 */
	public static function logSecurityAlert(?string $jailTag = 'security', ?string $ip = null, ?string $message = ''): void {
		$jailTag = $jailTag ?: 'security';
		if ($ip === null || !filter_var($ip, FILTER_VALIDATE_IP)) {
			$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
		}

		$date = date('Y-m-d H:i:s');
		$line = sprintf("%s [%s] %s - %s\n", $date, $jailTag, $ip, $message ?? '');

		@file_put_contents(self::SECURITY_LOG, $line, FILE_APPEND | LOCK_EX);
	}

	/**
	 * Read the last lines of a log file for live monitoring.
	 *
	 * @param string|null $type  'security' or 'fail2ban'
	 * @param int|null    $lines Number of lines to tail
	 * @return list<string>
	 */
	public static function tailLog(?string $type = 'security', ?int $lines = 80): array {
		$type = $type ?: 'security';
		$path = ($type === 'fail2ban') ? self::FAIL2BAN_LOG : self::SECURITY_LOG;
		if (!file_exists($path)) {
			return ["Log file {$path} does not exist yet."];
		}

		$lines = max(10, min(500, (int) ($lines ?? 80)));
		$output = [];
		@exec('tail -n ' . (int) $lines . ' ' . escapeshellarg($path) . ' 2>/dev/null', $output);

		return $output;
	}

	/**
	 * Retrieve recent history of bans and unbans from the module history table.
	 *
	 * @param int|null $limit
	 * @return list<array<string, mixed>>
	 */
	public static function getRecentHistory(?int $limit = 50): array {
		$limit = max(10, min(200, (int) ($limit ?? 50)));
		$db = self::db();
		try {
			$res = $db->query(
				'SELECT `id`, `ip`, `jail`, `action`, `reason`, `date` FROM `module_firewall_history` ORDER BY `id` DESC LIMIT ' . (int) $limit
			);
			if ($res) {
				return $db->get_rows() ?: [];
			}
		} catch (\Throwable) {
		}

		return [];
	}

	/**
	 * Synchronize all currently banned IPs from Fail2ban active jails into the `blocked_ips` table and cluster.
	 *
	 * @return int Number of IPs synchronized.
	 */
	public static function syncFromFail2ban(): int {
		$status = self::getJailsStatus();
		if (empty($status['running'])) {
			return 0;
		}

		$db = self::db();
		$syncedCount = 0;
		$allBanned = [];

		foreach ($status['jails'] ?? [] as $jailName => $jData) {
			foreach ($jData['banned_ips'] ?? [] as $ip) {
				if (filter_var($ip, FILTER_VALIDATE_IP)) {
					$allBanned[$ip] = $jailName;
				}
			}
		}

		foreach ($allBanned as $ip => $jailName) {
			try {
				$note = "Fail2ban: {$jailName}";
				$db->query(
					'INSERT INTO `blocked_ips` (`ip`, `notes`, `date`) VALUES (?, ?, ?)
					 ON DUPLICATE KEY UPDATE `notes` = VALUES(`notes`), `date` = VALUES(`date`)',
					$ip,
					$note,
					time()
				);
				$syncedCount++;
			} catch (\Throwable) {
			}
		}

		if (!empty($allBanned)) {
			try {
				BlocklistChanges::set('ip', array_keys($allBanned), $db);
			} catch (\Throwable) {
			}
		}

		return $syncedCount;
	}

	/**
	 * Retrieve comprehensive monitor telemetry, process info, and system diagnostics.
	 *
	 * @return array<string, mixed>
	 */
	public static function getMonitorData(): array {
		$status = self::getJailsStatus();
		$settings = self::getSettings();
		$history = self::getRecentHistory(15);
		$securityFeed = self::tailLog('security', 15);
		$fail2banFeed = self::tailLog('fail2ban', 15);

		// Process diagnostics
		$vOut = [];
		@exec('fail2ban-client --version 2>/dev/null', $vOut);
		$version = trim($vOut[0] ?? 'Fail2Ban v1.0.2');

		$pid = 0;
		$pidOut = [];
		@exec('pgrep -x fail2ban-server 2>/dev/null', $pidOut);
		if (!empty($pidOut[0])) {
			$pid = (int) $pidOut[0];
		}

		$uptime = 'N/A';
		if ($pid > 0) {
			$etimeOut = [];
			@exec('ps -o etime= -p ' . $pid . ' 2>/dev/null', $etimeOut);
			$uptime = trim($etimeOut[0] ?? 'Running');
		}

		// Count blocked_ips in database
		$dbBlocked = 0;
		try {
			$db = self::db();
			$res = $db->query('SELECT COUNT(*) AS `cnt` FROM `blocked_ips`');
			if ($res) {
				$row = $db->get_row();
				$dbBlocked = (int) ($row['cnt'] ?? 0);
			}
		} catch (\Throwable) {
		}

		// Calculate total currently failed across all jails
		$totalCurrentlyFailed = 0;
		foreach ($status['jails'] ?? [] as $j) {
			$totalCurrentlyFailed += (int) ($j['currently_failed'] ?? 0);
		}

		return [
			'status'                 => $status,
			'settings'               => $settings,
			'history'                => $history,
			'security_feed'          => $securityFeed,
			'fail2ban_feed'          => $fail2banFeed,
			'version'                => $version,
			'pid'                    => $pid,
			'uptime'                 => $uptime,
			'db_blocked_count'       => $dbBlocked,
			'total_currently_failed' => $totalCurrentlyFailed,
		];
	}
}
