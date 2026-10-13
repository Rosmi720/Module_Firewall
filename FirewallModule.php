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

use XcVm\Cli\CommandRegistry;
use XcVm\Core\Container\ServiceContainer;
use XcVm\Core\Http\Router;
use XcVm\Core\Module\BaseModule;
use XcVm\Core\Module\Contract\CommandProviderInterface;
use XcVm\Core\Module\Contract\CronProviderInterface;
use XcVm\Core\Module\Contract\NavbarProviderInterface;
use XcVm\Core\Module\Contract\RouteProviderInterface;
use XcVm\Core\Module\NavbarItem;
use XcVm\Core\Module\NavbarRegistry;

/**
 * FirewallModule — Main module definition for Firewall & Fail2ban Suite.
 *
 * Integrates:
 * - Admin web UI and REST API
 * - Navbar menu item under Security & Tools
 * - CLI commands and cron synchronization
 * - Fail2ban jails configuration and lifecycle hooks
 * - Multi-language support (English & Arabic)
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallModule extends BaseModule implements RouteProviderInterface, NavbarProviderInterface, CommandProviderInterface, CronProviderInterface {

	public function getName(): string {
		return 'firewall';
	}

	public function getVersion(): string {
		return '1.0.0';
	}

	public function boot(ServiceContainer $container): void {
		FirewallTranslator::init();
		FirewallService::initTables();

		if (!is_dir(FirewallService::LOG_DIR)) {
			@mkdir(FirewallService::LOG_DIR, 0755, true);
		}
		if (!file_exists(FirewallService::SECURITY_LOG)) {
			@touch(FirewallService::SECURITY_LOG);
			@chmod(FirewallService::SECURITY_LOG, 0666);
		}
	}

	/**
	 * Self-setup hook executed on module installation.
	 */
	public function install(): void {
		FirewallTranslator::init();
		FirewallService::initTables();
		FirewallService::deployConfigs();
	}

	/**
	 * Self-teardown hook executed on module uninstallation.
	 */
	public function uninstall(): void {
		// Do not drop core blocked_ips, but clean up module config if desired
	}

	/**
	 * Register HTTP routes and API endpoints.
	 */
	public function registerRoutes(Router $router): void {
		// Group 'firewall' (Router normalizes firewall_settings -> firewall/settings)
		$router->group('firewall', function (Router $r) {
			$r->any('', [FirewallController::class, 'dashboard']);
			$r->any('dashboard', [FirewallController::class, 'dashboard']);
			$r->any('rules', [FirewallController::class, 'rules']);
			$r->any('settings', [FirewallController::class, 'settings']);
			$r->any('logs', [FirewallController::class, 'logs']);
		});

		// Flat routes (no sub-folders, clean access-code friendly URLs)
		$router->any('firewall', [FirewallController::class, 'dashboard']);
		$router->any('firewall_dashboard', [FirewallController::class, 'dashboard']);
		$router->any('firewall_rules', [FirewallController::class, 'rules']);
		$router->any('firewall_settings', [FirewallController::class, 'settings']);
		$router->any('firewall_logs', [FirewallController::class, 'logs']);

		// API endpoints
		$router->api('firewall_get_status', [FirewallController::class, 'apiGetStatus']);
		$router->api('firewall_get_monitor', [FirewallController::class, 'apiGetMonitor']);
		$router->api('firewall_service_control', [FirewallController::class, 'apiServiceControl']);
		$router->api('firewall_deploy', [FirewallController::class, 'apiDeploy']);
		$router->api('firewall_sync', [FirewallController::class, 'apiSync']);
		$router->api('firewall_install', [FirewallController::class, 'apiInstall']);
		$router->api('firewall_save_settings', [FirewallController::class, 'apiSaveSettings']);
		$router->api('firewall_unban', [FirewallController::class, 'apiUnban']);
		$router->api('firewall_ban', [FirewallController::class, 'apiBan']);
		$router->api('firewall_get_logs', [FirewallController::class, 'apiGetLogs']);

		// Rules Engine APIs
		$router->api('firewall_get_rules', [FirewallController::class, 'apiGetRules']);
		$router->api('firewall_save_rule', [FirewallController::class, 'apiSaveRule']);
		$router->api('firewall_delete_rule', [FirewallController::class, 'apiDeleteRule']);
		$router->api('firewall_toggle_rule', [FirewallController::class, 'apiToggleRule']);
		$router->api('firewall_reset_default_rules', [FirewallController::class, 'apiResetDefaultRules']);
		$router->api('firewall_test_regex', [FirewallController::class, 'apiTestRegex']);
	}

	/**
	 * Register CLI commands for console runner.
	 */
	public function registerCommands(CommandRegistry $registry): void {
		$registry->register(new FirewallSyncCommand());
		$registry->register(new FirewallManageCommand());
		$registry->register(new FirewallCronJob());
	}

	/**
	 * Register system crontab entries.
	 */
	public function getCronEntries(): array {
		return [
			'*/5 * * * *' => 'cron:firewall_sync',
		];
	}

	/**
	 * Register items in the Admin Navbar.
	 */
	public function registerNavbar(NavbarRegistry $registry): void {
		FirewallTranslator::init();

		// Parent menu item
		$registry->add((new NavbarItem('firewall'))
			->url('#')
			->label('firewall_nav_title', 'Firewall & Fail2ban')
			->icon('ti tabler-shield-lock')
			->order(335));

		// Submenu items
		$registry->add((new NavbarItem('firewall.dashboard'))
			->parent('firewall')
			->url('firewall')
			->label('firewall_nav_dashboard', 'Dashboard')
			->order(10));

		$registry->add((new NavbarItem('firewall.rules'))
			->parent('firewall')
			->url('firewall_rules')
			->label('firewall_nav_rules', 'Security Rules')
			->order(15));

		$registry->add((new NavbarItem('firewall.settings'))
			->parent('firewall')
			->url('firewall_settings')
			->label('firewall_nav_settings', 'Settings & Jails')
			->order(20));

		$registry->add((new NavbarItem('firewall.logs'))
			->parent('firewall')
			->url('firewall_logs')
			->label('firewall_nav_logs', 'Live Logs')
			->order(30));
	}
}

