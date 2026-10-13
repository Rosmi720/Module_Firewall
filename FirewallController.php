<?php

namespace XcVm\Module\Firewall;

use XcVm\Core\Util\LayoutRenderer;

/**
 * FirewallController — Web Controller and Admin API Handler for Firewall & Fail2ban.
 *
 * Provides endpoints for:
 * - Dashboard with real-time stats and banned IP list
 * - Settings view for jail sensitivity and whitelist management
 * - Live log viewer for fail2ban and security events
 * - REST API endpoints for async operations
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallController {

	protected string $viewsPath;

	public function __construct() {
		$this->viewsPath = __DIR__ . '/views';
		FirewallTranslator::init();
	}

	/**
	 * Guard: Ensure only authenticated administrators can access.
	 */
	protected function ensureAdmin(): void {
		if (php_sapi_name() === 'cli') {
			return;
		}
		global $rUserInfo;
		$isAdmin = !empty($rUserInfo['is_admin']) || (intval($rUserInfo['member_group_id'] ?? 0) === 1);

		if (!$isAdmin) {
			http_response_code(403);
			if (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json')) {
				header('Content-Type: application/json; charset=utf-8');
				echo json_encode(['status' => 'error', 'message' => 'Forbidden: Administrator privileges required.']);
			} else {
				echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Administrator privileges required.</p></body></html>';
			}
			exit;
		}
	}

	/**
	 * Guard against nested path slashes (e.g. /{CODE}/firewall/settings) which break
	 * relative asset URLs (assets/...) in header.php. Redirects cleanly via HTTP 302
	 * to canonical flat URLs.
	 */
	protected function ensureCanonicalUrl(): void {
		if (php_sapi_name() === 'cli') {
			return;
		}
		$uri = (string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
		$code = (string) ($_SERVER['XC_CODE'] ?? '');
		if ($code === '') {
			$parts = explode('/', trim($uri, '/'));
			if (!empty($parts[0]) && !str_starts_with($parts[0], 'firewall')) {
				$code = $parts[0];
			}
		}

		$base = $code !== '' ? '/' . $code . '/' : '';

		// If accessed via nested slash (e.g. /3yRv7Adq/firewall/settings or /3yRv7Adq/firewall/)
		if (preg_match('#/firewall/(rules|settings|logs|dashboard|index)?/?$#i', $uri, $m)) {
			$sub = strtolower($m[1] ?? '');
			$target = match ($sub) {
				'rules'    => $base . 'firewall_rules',
				'settings' => $base . 'firewall_settings',
				'logs'     => $base . 'firewall_logs',
				default    => $base . 'firewall',
			};
			header('Location: ' . $target, true, 302);
			exit;
		}

		// Trailing slash on /firewall/ -> redirect to /firewall
		if (str_ends_with($uri, '/firewall/')) {
			header('Location: ' . $base . 'firewall', true, 302);
			exit;
		}
	}

	/**
	 * Render an admin view wrapped with standard XC_VM layout.
	 *
	 * @param string               $title Page title
	 * @param string               $view  View name inside views/
	 * @param array<string, mixed> $vars  Variables to pass to view
	 */
	protected function render(string $title, string $view, array $vars = []): void {
		$this->ensureCanonicalUrl();
		$this->ensureAdmin();
		global $rUserInfo, $rSettings, $rMobile, $rServers, $rPermissions, $_STATUS;
		$rMobile = (bool) ($rMobile ?? false);
		if (!is_array($rUserInfo)) {
			$rUserInfo = [
				'username'        => 'admin',
				'is_admin'        => 1,
				'member_group_id' => 1,
				'theme'           => 0,
				'ui_prefs'        => ''
			];
		} elseif (empty($rUserInfo['username'])) {
			$rUserInfo['username'] = 'admin';
		}
		FirewallTranslator::init();
		$language = FirewallTranslator::class;
		extract($vars);

		LayoutRenderer::renderHeader('admin', ['_TITLE' => $title]);
		$cssFile = $this->viewsPath . '/firewall.css';
		if (file_exists($cssFile)) {
			echo '<style>' . file_get_contents($cssFile) . '</style>';
		}
		include $this->viewsPath . '/' . $view . '.php';
		LayoutRenderer::renderFooter('admin');
		include $this->viewsPath . '/scripts.php';
	}


	/**
	 * Send JSON response and exit cleanly.
	 *
	 * @param array<string, mixed> $data
	 */
	protected function json(array $data): void {
		header('Content-Type: application/json; charset=utf-8');
		echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
		exit;
	}

	// ───────────────────────────────────────────────────────────
	//  Admin Views
	// ───────────────────────────────────────────────────────────

	/**
	 * Firewall & Fail2ban Dashboard view.
	 */
	public function dashboard(): void {
		$this->ensureCanonicalUrl();
		$this->ensureAdmin();

		$monitor           = FirewallService::getMonitorData();
		$status            = $monitor['status'];
		$settings          = $monitor['settings'];
		$history           = $monitor['history'];
		$versionInfo       = $monitor['version_info'] ?? FirewallService::checkFail2banVersions();
		$onboardingNeeded  = $monitor['onboarding_needed'] ?? FirewallService::isOnboardingNeeded();
		$autoDetectedEnv   = FirewallService::detectEnvironmentDetails();
		$title             = FirewallTranslator::get('firewall_dashboard_title', 'Firewall & Fail2ban Security Suite');

		$this->render($title, 'dashboard', compact(
			'monitor',
			'status',
			'settings',
			'history',
			'versionInfo',
			'onboardingNeeded',
			'autoDetectedEnv'
		));
	}

	/**
	 * Firewall & Security Rules management view.
	 */
	public function rules(): void {
		$this->ensureCanonicalUrl();
		$this->ensureAdmin();

		$rules  = FirewallService::getAllRules();
		$status = FirewallService::getJailsStatus();
		$title  = FirewallTranslator::get('firewall_rules_title', 'Firewall & Security Rules');

		$this->render($title, 'rules', compact('rules', 'status'));
	}


	/**
	 * Firewall Settings & Jails Configuration view.
	 */
	public function settings(): void {
		$this->ensureCanonicalUrl();
		$this->ensureAdmin();

		$settings = FirewallService::getSettings();
		$status   = FirewallService::getJailsStatus();
		$title    = FirewallTranslator::get('firewall_settings_title', 'Firewall Settings & Jails');

		$this->render($title, 'settings', compact('settings', 'status'));
	}

	/**
	 * Live Security Logs Viewer.
	 */
	public function logs(): void {
		$this->ensureCanonicalUrl();
		$this->ensureAdmin();

		$securityLogs = FirewallService::tailLog('security', 100);
		$fail2banLogs = FirewallService::tailLog('fail2ban', 100);
		$title        = FirewallTranslator::get('firewall_logs_title', 'Firewall & Fail2ban Live Logs');

		$this->render($title, 'logs', compact('securityLogs', 'fail2banLogs'));
	}

	// ───────────────────────────────────────────────────────────
	//  API Endpoints
	// ───────────────────────────────────────────────────────────

	/**
	 * API: Get live status of Fail2ban service and active jails.
	 */
	public function apiGetStatus(): void {
		$this->ensureAdmin();
		$status = FirewallService::getJailsStatus();
		$this->json([
			'status' => 'success',
			'data'   => $status,
		]);
	}

	/**
	 * API: Control Fail2ban service (start, stop, restart, reload).
	 */
	public function apiServiceControl(): void {
		$this->ensureAdmin();
		$action = trim((string) ($_POST['service_action'] ?? $_POST['action'] ?? $_REQUEST['service_action'] ?? ''));

		$success = false;
		$msg = '';

		switch ($action) {
			case 'start':
				$success = FirewallService::start();
				$msg = $success ? 'Fail2ban service started successfully.' : 'Failed to start Fail2ban.';
				break;
			case 'stop':
				$success = FirewallService::stop();
				$msg = $success ? 'Fail2ban service stopped.' : 'Failed to stop Fail2ban.';
				break;
			case 'restart':
				$success = FirewallService::restart();
				$msg = $success ? 'Fail2ban service restarted successfully.' : 'Failed to restart Fail2ban.';
				break;
			case 'reload':
				$success = FirewallService::reload();
				$msg = $success ? 'Fail2ban rules reloaded.' : 'Failed to reload Fail2ban.';
				break;
			default:
				$this->json(['status' => 'error', 'message' => 'Invalid action requested.']);
				return;
		}

		$this->json([
			'status'  => $success ? 'success' : 'error',
			'message' => $msg,
		]);
	}

	/**
	 * API: Install Fail2ban package and deploy configs.
	 */
	public function apiInstall(): void {
		$this->ensureAdmin();
		$res = FirewallService::installPackage();

		$this->json([
			'status'  => $res['success'] ? 'success' : 'error',
			'message' => $res['message'],
		]);
	}

	/**
	 * API: Save updated jail rules and whitelist settings.
	 */
	public function apiSaveSettings(): void {
		$this->ensureAdmin();

		$preset = (string) ($_POST['preset'] ?? 'balanced');
		$ignoreip = (string) ($_POST['ignoreip'] ?? '');
		$syncToDb = !empty($_POST['sync_to_db']);

		$jails = [];
		if (isset($_POST['jails']) && is_array($_POST['jails'])) {
			$jails = $_POST['jails'];
		}

		$saved = FirewallService::saveSettings([
			'preset'     => $preset,
			'ignoreip'   => $ignoreip,
			'sync_to_db' => $syncToDb,
			'jails'      => $jails,
		]);

		$this->json([
			'status'  => $saved ? 'success' : 'error',
			'message' => $saved ? FirewallTranslator::get('firewall_settings_saved') : 'Failed to save settings.',
		]);
	}

	/**
	 * API: Unban an IP address.
	 */
	public function apiUnban(): void {
		$this->ensureAdmin();

		$ip   = trim((string) ($_POST['ip'] ?? ''));
		$jail = trim((string) ($_POST['jail'] ?? ''));

		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			$this->json(['status' => 'error', 'message' => 'Invalid IP address provided.']);
			return;
		}

		$unbanned = FirewallService::unbanIp($ip, !empty($jail) ? $jail : null);

		$this->json([
			'status'  => $unbanned ? 'success' : 'error',
			'message' => $unbanned ? "Successfully unbanned IP: {$ip}" : "Failed to unban IP: {$ip}",
		]);
	}

	/**
	 * API: Manually ban an IP address.
	 */
	public function apiBan(): void {
		$this->ensureAdmin();

		$ip     = trim((string) ($_POST['ip'] ?? ''));
		$jail   = trim((string) ($_POST['jail'] ?? 'xcvm-panel'));
		$reason = trim((string) ($_POST['reason'] ?? 'Manual ban from Admin panel'));

		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			$this->json(['status' => 'error', 'message' => 'Invalid IP address provided.']);
			return;
		}

		$banned = FirewallService::banIp($ip, $jail, $reason);

		$this->json([
			'status'  => $banned ? 'success' : 'error',
			'message' => $banned ? "Successfully banned IP: {$ip} in {$jail}" : "Failed to ban IP: {$ip}",
		]);
	}

	/**
	 * API: Get live logs.
	 */
	public function apiGetLogs(): void {
		$this->ensureAdmin();

		$type  = (string) ($_GET['type'] ?? 'security');
		$lines = max(10, min(300, (int) ($_GET['lines'] ?? 100)));

		$logs = FirewallService::tailLog($type, $lines);

		$this->json([
			'status' => 'success',
			'data'   => [
				'type'  => $type,
				'lines' => $logs,
			],
		]);
	}

	/**
	 * API: Get full live monitor and telemetry data for live dashboard updates.
	 */
	public function apiGetMonitor(): void {
		$this->ensureAdmin();
		$monitor = FirewallService::getMonitorData();
		$this->json([
			'status' => 'success',
			'data'   => $monitor,
		]);
	}

	/**
	 * API: Re-deploy filter rules and reload Fail2ban.
	 */
	public function apiDeploy(): void {
		$this->ensureAdmin();
		$deployed = FirewallService::deployConfigs();
		if (!$deployed) {
			$this->json([
				'status'  => 'error',
				'message' => 'Failed to deploy configuration files. Please check filesystem permissions.',
			]);
			return;
		}
		$reloaded = FirewallService::reload();
		$this->json([
			'status'  => $reloaded ? 'success' : 'error',
			'message' => $reloaded ? FirewallTranslator::get('firewall_deploy_success', 'Security rules deployed and Fail2ban reloaded successfully.') : 'Failed to reload Fail2ban after deploying rules.',
		]);
	}

	/**
	 * API: Sync active Fail2ban bans to database and cluster nodes.
	 */
	public function apiSync(): void {
		$this->ensureAdmin();
		$count = FirewallService::syncFromFail2ban();
		$this->json([
			'status'  => 'success',
			'message' => FirewallTranslator::get('firewall_sync_success', 'Banned IPs synchronized with database and cluster.') . " ({$count} IPs)",
			'data'    => ['count' => $count],
		]);
	}

	/**
	 * API: Get all firewall rules.
	 */
	public function apiGetRules(): void {
		$this->ensureAdmin();
		$rules = FirewallService::getAllRules();
		$this->json([
			'status' => 'success',
			'data'   => $rules,
		]);
	}

	/**
	 * API: Save (create or update) a firewall rule.
	 */
	public function apiSaveRule(): void {
		$this->ensureAdmin();

		$res = FirewallService::saveRule($_POST);

		$this->json([
			'status'  => $res['success'] ? 'success' : 'error',
			'message' => $res['message'],
		]);
	}

	/**
	 * API: Delete a custom firewall rule.
	 */
	public function apiDeleteRule(): void {
		$this->ensureAdmin();

		$ruleKey = trim((string) ($_POST['rule_key'] ?? $_POST['key'] ?? ''));
		$res = FirewallService::deleteRule($ruleKey);

		$this->json([
			'status'  => $res['success'] ? 'success' : 'error',
			'message' => $res['message'],
		]);
	}

	/**
	 * API: Toggle rule status (enable/disable).
	 */
	public function apiToggleRule(): void {
		$this->ensureAdmin();

		$ruleKey = trim((string) ($_POST['rule_key'] ?? $_POST['key'] ?? ''));
		$enabled = isset($_POST['enabled']) ? (bool) $_POST['enabled'] : null;

		$res = FirewallService::toggleRule($ruleKey, $enabled);

		$this->json([
			'status'  => $res['success'] ? 'success' : 'error',
			'message' => $res['message'],
		]);
	}

	/**
	 * API: Reset default core rules to factory defaults.
	 */
	public function apiResetDefaultRules(): void {
		$this->ensureAdmin();

		$success = FirewallService::resetDefaultRules();

		$this->json([
			'status'  => $success ? 'success' : 'error',
			'message' => $success ? FirewallTranslator::get('firewall_rules_reset_success', 'Default core rules reset to factory configuration.') : 'Failed to reset rules.',
		]);
	}

	/**
	 * API: Test regex against sample log.
	 */
	public function apiTestRegex(): void {
		$this->ensureAdmin();

		$regex     = (string) ($_POST['regex'] ?? '');
		$sampleLog = (string) ($_POST['sample_log'] ?? '');

		$res = FirewallService::testRegex($regex, $sampleLog);

		$this->json([
			'status'  => $res['success'] ? 'success' : 'error',
			'matches' => $res['matches'],
			'message' => $res['message'],
		]);
	}

	/**
	 * API: Check Fail2ban versions (local vs official upstream release).
	 */
	public function apiCheckVersions(): void {
		$this->ensureAdmin();
		$force = !empty($_GET['force']) || !empty($_POST['force']);
		$data = FirewallService::checkFail2banVersions((bool) $force);
		$this->json(['status' => 'success', 'data' => $data]);
	}

	/**
	 * API: Upgrade Fail2ban system package.
	 */
	public function apiUpgradeFail2ban(): void {
		$this->ensureAdmin();
		$res = FirewallService::upgradeFail2ban();
		$this->json($res);
	}

	/**
	 * API: Complete first-time onboarding setup and deploy protection suite.
	 */
	public function apiCompleteOnboarding(): void {
		$this->ensureAdmin();
		$params = $_POST;
		$res = FirewallService::runOnboarding($params);
		$this->json($res);
	}
}


