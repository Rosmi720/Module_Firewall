<?php
use XcVm\Module\Firewall\FirewallService;
use XcVm\Module\Firewall\FirewallTranslator;

/** @var array $monitor */
/** @var array $status */
/** @var array $settings */
/** @var array $history */

$language    = FirewallTranslator::class;
$isInstalled = !empty($status['installed']);
$isRunning   = !empty($status['running']);
$totalBanned = (int) ($status['total_banned'] ?? 0);
$jails       = $status['jails'] ?? [];
$rules       = FirewallService::getAllRules();

$version      = $monitor['version'] ?? 'Fail2Ban v1.0.2';
$pid          = (int) ($monitor['pid'] ?? 0);
$uptime       = $monitor['uptime'] ?? 'N/A';
$dbBlocked    = (int) ($monitor['db_blocked_count'] ?? 0);
$totalFailed  = (int) ($monitor['total_currently_failed'] ?? 0);
$fail2banFeed = $monitor['fail2ban_feed'] ?? [];
$securityFeed = $monitor['security_feed'] ?? [];

$jailIcons = [
	'sshd'          => 'ti tabler-terminal',
	'xcvm-panel'    => 'ti tabler-user-shield',
	'xcvm-stream'   => 'ti tabler-player-play',
	'xcvm-flood'    => 'ti tabler-flame',
	'xcvm-bots'     => 'ti tabler-robot',
	'xcvm-portscan' => 'ti tabler-radar',
];
?>

<div class="container-xxl flex-grow-1 container-p-y">

	<!-- Header Hero Bar -->
	<div class="card border-0 shadow-sm mb-4">
		<div class="card-body p-4">
			<!-- Part 1: System Telemetry & Details -->
			<div class="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
				<div class="d-flex align-items-center gap-3">
					<div class="avatar avatar-xl bg-label-primary rounded-circle d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-shield-lock fs-1"></i>
					</div>
					<div>
						<div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
							<h4 class="fw-bold mb-0 text-dark"><?= htmlspecialchars($language::get('firewall_dashboard_title', 'Firewall & Fail2ban Security Suite')); ?></h4>
							<?php if ($isRunning): ?>
								<span class="badge bg-label-success rounded-pill px-3 py-1 d-flex align-items-center gap-1">
									<span class="fw-pulse-dot active me-1"></span><?= htmlspecialchars($language::get('firewall_status_active', 'Active & Protecting')); ?>
								</span>
							<?php elseif ($isInstalled): ?>
								<span class="badge bg-label-danger rounded-pill px-3 py-1 d-flex align-items-center gap-1">
									<span class="fw-pulse-dot inactive me-1"></span><?= htmlspecialchars($language::get('firewall_status_inactive', 'Service Inactive')); ?>
								</span>
							<?php else: ?>
								<span class="badge bg-label-warning rounded-pill px-3 py-1">
									<i class="ti tabler-alert-triangle me-1"></i><?= htmlspecialchars($language::get('firewall_status_not_installed', 'Not Installed')); ?>
								</span>
							<?php endif; ?>

							<!-- Live Telemetry Badges -->
							<span class="badge bg-label-info rounded-pill font-monospace" id="badgeVersion"><?= htmlspecialchars($version); ?></span>
							<?php if ($pid > 0): ?>
								<span class="badge bg-label-secondary rounded-pill font-monospace" id="badgePid">PID: <?= $pid; ?></span>
								<span class="badge bg-label-dark rounded-pill font-monospace">
									<i class="ti tabler-clock me-1"></i><span id="badgeUptime"><?= htmlspecialchars($uptime); ?></span>
								</span>
							<?php endif; ?>
							<span class="badge bg-label-primary rounded-pill font-monospace"><?= htmlspecialchars($language::get('firewall_kernel_sync', 'Kernel Netfilter Synced')); ?></span>
						</div>
						<p class="text-muted mb-0">
							<?= htmlspecialchars($language::get('firewall_dashboard_desc', 'Enterprise-grade intrusion prevention, automated brute-force mitigation, and synchronized network blocklists.')); ?>
						</p>
					</div>
				</div>

				<!-- Quick Health Indicator -->
				<div class="d-none d-lg-flex align-items-center gap-2 bg-light rounded px-3 py-2 border">
					<i class="ti tabler-server-shield fs-2 text-primary"></i>
					<div>
						<small class="text-muted d-block fw-semibold">Defense Engine</small>
						<span class="badge bg-label-<?= $isRunning ? 'success' : 'danger'; ?> fw-bold font-monospace">
							<?= $isRunning ? 'fail2ban-server: ACTIVE' : 'fail2ban-server: STOPPED'; ?>
						</span>
					</div>
				</div>
			</div>

			<!-- Part 2: Actions Toolbar (Underneath Details) -->
			<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 border-top pt-3 mt-3">
				<!-- Left Operations & Controls -->
				<div class="d-flex flex-wrap align-items-center gap-2">
					<!-- Auto Refresh Switch (SOC Live Radar) -->
					<div class="fw-soc-toggle-wrapper d-inline-flex align-items-center me-1" id="fwSocToggleWrapper">
						<div class="fw-soc-toggle-pill d-flex align-items-center gap-2 px-3 py-1 rounded" id="fwSocTogglePill" title="<?= htmlspecialchars($language::get('firewall_live_refresh_desc', 'Auto-refresh live telemetry feed and statistics every 10 seconds')); ?>" onclick="fwClickSocPill(event)">
							<span class="fw-soc-beacon position-relative d-flex align-items-center justify-content-center flex-shrink-0">
								<span class="fw-soc-beacon-ring" id="liveRefreshPulse"></span>
								<i class="ti tabler-radar fw-soc-beacon-icon"></i>
							</span>
							<div class="d-flex flex-column justify-content-center lh-sm me-1 user-select-none">
								<span class="fw-soc-label text-nowrap"><?= htmlspecialchars($language::get('firewall_auto_refresh_badge', 'Live SOC')); ?></span>
								<span class="fw-soc-sublabel font-monospace text-nowrap" id="fwLiveStatusBadge"
									data-text-active="10s &bull; <?= htmlspecialchars($language::get('firewall_live_active', 'Active')); ?>"
									data-text-paused="10s &bull; <?= htmlspecialchars($language::get('firewall_live_paused', 'Paused')); ?>">
									10s &bull; <?= htmlspecialchars($language::get('firewall_live_paused', 'Paused')); ?>
								</span>
							</div>
							<div class="form-check form-switch mb-0 ms-1 p-0 d-flex align-items-center">
								<input class="form-check-input fw-soc-switch-input m-0" type="checkbox" role="switch" id="switchAutoRefresh" onchange="fwToggleAutoRefresh(this)">
							</div>
						</div>
					</div>

					<?php if ($isInstalled): ?>
						<?php if ($isRunning): ?>
							<button type="button" class="btn btn-outline-danger" onclick="fwServiceAction('stop')" title="<?= htmlspecialchars($language::get('firewall_stop_service', 'Stop')); ?>">
								<i class="ti tabler-player-stop me-1"></i><?= htmlspecialchars($language::get('firewall_stop_service', 'Stop')); ?>
							</button>
							<button type="button" class="btn btn-outline-secondary" onclick="fwServiceAction('restart')" title="<?= htmlspecialchars($language::get('firewall_restart_service', 'Restart')); ?>">
								<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_restart_service', 'Restart')); ?>
							</button>
							<button type="button" class="btn btn-outline-primary" onclick="fwServiceAction('reload')" title="<?= htmlspecialchars($language::get('firewall_reload_rules', 'Reload')); ?>">
								<i class="ti tabler-reload me-1"></i><?= htmlspecialchars($language::get('firewall_reload_rules', 'Reload')); ?>
							</button>
						<?php else: ?>
							<button type="button" class="btn btn-success" onclick="fwServiceAction('start')">
								<i class="ti tabler-player-play me-1"></i><?= htmlspecialchars($language::get('firewall_start_service', 'Start')); ?>
							</button>
						<?php endif; ?>

						<!-- Deploy Rules & Cluster Sync Action Buttons -->
						<button type="button" class="btn btn-outline-warning" onclick="fwDeploy()" title="<?= htmlspecialchars($language::get('firewall_deploy_now', 'Deploy Rules')); ?>">
							<i class="ti tabler-file-code me-1"></i><?= htmlspecialchars($language::get('firewall_deploy_now', 'Deploy Rules')); ?>
						</button>
						<button type="button" class="btn btn-outline-info" onclick="fwSync()" title="<?= htmlspecialchars($language::get('firewall_sync_now', 'Sync Cluster')); ?>">
							<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_sync_now', 'Sync Cluster')); ?>
						</button>

						<button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#modalManualBan">
							<i class="ti tabler-ban me-1"></i><?= htmlspecialchars($language::get('firewall_manual_ban', 'Ban IP')); ?>
						</button>
					<?php else: ?>
						<button type="button" class="btn btn-primary btn-lg fw-bold shadow-sm" id="btnInstallFail2ban" onclick="fwInstall()">
							<i class="ti tabler-download me-2"></i><?= htmlspecialchars($language::get('firewall_install_now', 'Install Fail2ban')); ?>
						</button>
					<?php endif; ?>
				</div>

				<!-- Right Navigation Shortcuts -->
				<div class="d-flex flex-wrap align-items-center gap-2">
					<a href="firewall_rules" class="btn btn-light border" title="<?= htmlspecialchars($language::get('firewall_rules_title', 'Security Rules')); ?>">
						<i class="ti tabler-list-check me-1 text-primary"></i><?= htmlspecialchars($language::get('firewall_nav_rules', 'Rules')); ?>
					</a>
					<a href="firewall_settings" class="btn btn-light border" title="<?= htmlspecialchars($language::get('firewall_settings', 'Settings')); ?>">
						<i class="ti tabler-settings me-1 text-secondary"></i><?= htmlspecialchars($language::get('firewall_settings', 'Settings')); ?>
					</a>
					<a href="firewall_logs" class="btn btn-light border" title="<?= htmlspecialchars($language::get('firewall_live_logs', 'Logs')); ?>">
						<i class="ti tabler-file-text me-1 text-info"></i><?= htmlspecialchars($language::get('firewall_live_logs', 'Logs')); ?>
					</a>
				</div>
			</div>
		</div>
	</div>


	<?php if (!$isInstalled): ?>
		<!-- Setup Notice Banner -->
		<div class="card border-primary mb-4 shadow-sm">
			<div class="card-body p-4 bg-label-primary rounded d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3">
				<div>
					<h5 class="fw-bold mb-1 text-primary"><i class="ti tabler-sparkles me-2"></i><?= htmlspecialchars($language::get('firewall_banner_title', 'Activate Server Security Suite')); ?></h5>
					<p class="mb-0 text-muted"><?= htmlspecialchars($language::get('firewall_banner_desc', 'Fail2ban package is not detected on this server. Install it now to enable automated brute-force protection and firewall jail enforcement.')); ?></p>
				</div>
				<button type="button" class="btn btn-primary btn-lg fw-bold text-nowrap" onclick="fwInstall()">
					<i class="ti tabler-download me-1"></i><?= htmlspecialchars($language::get('firewall_banner_btn', 'Install Fail2ban Now')); ?>
				</button>
			</div>
		</div>
	<?php endif; ?>

	<!-- Stats Telemetry Row (6 Stat Cards) — Styled identically to reference design system -->
	<div class="row g-3 mb-4">
		<!-- Total Banned IPs -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-danger rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-shield-x fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_total_banned', 'Live Banned IPs')); ?></small>
						<h4 class="mb-0 fw-bold text-danger" id="statTotalBanned"><?= $totalBanned; ?></h4>
					</div>
				</div>
			</div>
		</div>

		<!-- Cluster DB Blocked IPs -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-primary rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-database fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_stat_db_blocked', 'DB Synced Blocklist')); ?></small>
						<h4 class="mb-0 fw-bold text-primary" id="statDbBlocked"><?= $dbBlocked; ?></h4>
					</div>
				</div>
			</div>
		</div>

		<!-- Active Protected Rules -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-info rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-list-check fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_active_jails', 'Active Security Rules')); ?></small>
						<h4 class="mb-0 fw-bold text-info"><?= count(array_filter($rules, fn($r) => !empty($r['enabled']))); ?></h4>
					</div>
				</div>
			</div>
		</div>

		<!-- Total Currently Failed -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-warning rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-alert-triangle fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_stat_total_failed', 'Attack Failures')); ?></small>
						<h4 class="mb-0 fw-bold text-warning" id="statTotalFailed"><?= $totalFailed; ?></h4>
					</div>
				</div>
			</div>
		</div>

		<!-- SSH Protection Bans -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-secondary rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-terminal-2 fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_ssh_banned', 'SSH Attack Bans')); ?></small>
						<h4 class="mb-0 fw-bold text-dark"><?= (int) ($jails['sshd']['currently_banned'] ?? 0); ?></h4>
					</div>
				</div>
			</div>
		</div>

		<!-- Stream & Panel Bans -->
		<div class="col-sm-6 col-lg-4 col-xl-2">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-success rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-video fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_stream_panel_banned', 'Web & Stream Bans')); ?></small>
						<h4 class="mb-0 fw-bold text-success"><?= (int) (($jails['xcvm-panel']['currently_banned'] ?? 0) + ($jails['xcvm-stream']['currently_banned'] ?? 0)); ?></h4>
					</div>
				</div>
			</div>
		</div>
	</div>

	<!-- Rules & Jails Workload Grid -->
	<div class="d-flex justify-content-between align-items-center mb-3">
		<div>
			<h5 class="fw-bold mb-0"><i class="ti tabler-layout-grid me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_tab_jails_monitor', 'Security Rules & Jails Telemetry')); ?></h5>
			<small class="text-muted"><?= htmlspecialchars($language::get('firewall_monitor_desc', 'Live workload, failure thresholds and ban enforcement across active rules')); ?></small>
		</div>
		<a href="firewall_rules" class="btn btn-sm btn-outline-primary">
			<i class="ti tabler-plus me-1"></i><?= htmlspecialchars($language::get('firewall_manage_rules', 'Manage All Rules')); ?>
		</a>
	</div>

	<div class="row g-3 mb-4">
		<?php foreach ($rules as $r): ?>
			<?php
			$ruleKey   = $r['rule_key'];
			$isActive  = !empty($r['enabled']) && isset($jails[$ruleKey]);
			$jData     = $jails[$ruleKey] ?? [];
			$curBanned = (int) ($jData['currently_banned'] ?? 0);
			$curFailed = (int) ($jData['currently_failed'] ?? 0);
			$maxretry  = max(1, (int) ($r['maxretry'] ?? 5));
			$findtime  = (int) ($r['findtime'] ?? 600);
			$bantime   = (int) ($r['bantime'] ?? 3600);
			$port      = (string) ($r['port'] ?? 'all');
			$icon      = $jailIcons[$ruleKey] ?? 'ti tabler-shield-check';

			$rawPct    = min(100, (int) (($curFailed / $maxretry) * 100));
			$gaugeStep = max(0, min(100, (int) (round($rawPct / 10) * 10)));
			?>
			<div class="col-sm-6 col-lg-4 col-xl-2">
				<div class="card border-0 shadow-sm h-100">
					<div class="card-body p-3 d-flex flex-column justify-content-between">
						<div>
							<div class="d-flex align-items-center justify-content-between mb-2">
								<div class="d-flex align-items-center gap-2">
									<i class="<?= $icon; ?> fs-4 text-primary"></i>
									<h6 class="fw-bold mb-0 text-truncate font-monospace"><?= htmlspecialchars($ruleKey); ?></h6>
								</div>
								<?php if ($isActive): ?>
									<span class="badge bg-label-success rounded-pill"><?= htmlspecialchars($language::get('firewall_active', 'Active')); ?></span>
								<?php elseif (!empty($r['enabled'])): ?>
									<span class="badge bg-label-warning rounded-pill"><?= htmlspecialchars($language::get('firewall_standby', 'Ready')); ?></span>
								<?php else: ?>
									<span class="badge bg-label-secondary rounded-pill"><?= htmlspecialchars($language::get('firewall_disabled', 'Disabled')); ?></span>
								<?php endif; ?>
							</div>

							<p class="text-muted small mb-2 text-truncate" title="<?= htmlspecialchars($r['name']); ?>">
								<?= htmlspecialchars($r['name']); ?>
							</p>

							<!-- Configuration Parameters Chip -->
							<div class="bg-light rounded p-2 mb-2 border small font-monospace">
								<div class="d-flex justify-content-between mb-1">
									<span class="text-muted"><?= htmlspecialchars($language::get('firewall_label_port', 'Port')); ?>:</span>
									<span class="fw-bold text-truncate"><?= htmlspecialchars($port); ?></span>
								</div>
								<div class="d-flex justify-content-between mb-1">
									<span class="text-muted"><?= htmlspecialchars($language::get('firewall_label_maxretry', 'Max Retry')); ?>:</span>
									<span><?= $maxretry; ?></span>
								</div>
								<div class="d-flex justify-content-between">
									<span class="text-muted"><?= htmlspecialchars($language::get('firewall_label_bantime', 'Ban Time')); ?>:</span>
									<span><?= $bantime; ?>s</span>
								</div>
							</div>

							<!-- Workload Progress Gauge (Zero Inline Styles) -->
							<div class="mb-2">
								<div class="d-flex justify-content-between small mb-1">
									<span class="text-muted"><?= htmlspecialchars($language::get('firewall_currently_failed', 'Failed')); ?>:</span>
									<span class="fw-bold <?= $curFailed > 0 ? 'text-warning' : 'text-muted'; ?>"><?= $curFailed; ?> / <?= $maxretry; ?></span>
								</div>
								<div class="progress fw-progress-track">
									<div class="progress-bar <?= $gaugeStep > 60 ? 'bg-danger' : ($gaugeStep > 30 ? 'bg-warning' : 'bg-success'); ?> fw-w-<?= $gaugeStep; ?>" role="progressbar"></div>
								</div>
							</div>
						</div>

						<div class="d-flex justify-content-between align-items-center pt-2 border-top">
							<span class="small text-muted"><?= htmlspecialchars($language::get('firewall_currently_banned', 'Banned')); ?>:</span>
							<span class="badge bg-label-danger font-monospace fs-6"><?= $curBanned; ?> IP</span>
						</div>
					</div>
				</div>
			</div>
		<?php endforeach; ?>
	</div>

	<!-- Two-Column Flex/Grid Monitoring Section (Active Bans Table + Live Threat Radar) -->
	<div class="row g-4 mb-4">
		<!-- Column 1: Active Banned IPs Table -->
		<div class="col-12 col-xl-7">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-header bg-transparent d-flex flex-wrap justify-content-between align-items-center p-3 gap-2 border-bottom">
					<div>
						<h5 class="fw-bold mb-0"><i class="ti tabler-ban me-2 text-danger"></i><?= htmlspecialchars($language::get('firewall_banned_table_title', 'Active Banned IP Addresses')); ?></h5>
						<small class="text-muted"><?= htmlspecialchars($language::get('firewall_banned_table_desc', 'Currently enforced firewall blocks across active jails and kernel netfilter')); ?></small>
					</div>
					<div class="d-flex gap-2">
						<input type="text" id="filterBannedInput" class="form-control form-control-sm fw-search-input" placeholder="<?= htmlspecialchars($language::get('firewall_search_ip', 'Search IP or jail...')); ?>">
					</div>
				</div>

				<div class="table-responsive">
					<table class="table table-hover align-middle mb-0" id="bannedTable">
						<thead class="table-light">
							<tr>
								<th><?= htmlspecialchars($language::get('firewall_col_ip', 'IP Address')); ?></th>
								<th><?= htmlspecialchars($language::get('firewall_col_jail', 'Jail / Rule')); ?></th>
								<th><?= htmlspecialchars($language::get('firewall_col_db_sync', 'Cluster Sync')); ?></th>
								<th class="no-sort text-end"><?= htmlspecialchars($language::get('firewall_col_actions', 'Action')); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php
							foreach ($jails as $jailName => $jData) {
								foreach ($jData['banned_ips'] ?? [] as $bIp) {
									?>
									<tr>
										<td>
											<div class="d-flex align-items-center gap-2 font-monospace fw-bold text-danger">
												<i class="ti tabler-shield-x"></i>
												<span><?= htmlspecialchars($bIp); ?></span>
											</div>
										</td>
										<td>
											<span class="badge bg-label-primary font-monospace"><?= htmlspecialchars($jailName); ?></span>
										</td>
										<td>
											<span class="badge bg-label-success">
												<i class="ti tabler-check me-1"></i><?= htmlspecialchars($language::get('firewall_synced', 'Synced')); ?>
											</span>
										</td>
										<td class="text-end">
											<button type="button" class="btn btn-sm btn-outline-success" onclick="fwUnban('<?= htmlspecialchars($bIp); ?>', '<?= htmlspecialchars($jailName); ?>')">
												<i class="ti tabler-check me-1"></i><?= htmlspecialchars($language::get('firewall_btn_unban', 'Unban')); ?>
											</button>
										</td>
									</tr>
									<?php
								}
							}
							?>
						</tbody>
					</table>
				</div>
			</div>
		</div>

		<!-- Column 2: Live SOC Threat Radar & Stream Feeds -->
		<div class="col-12 col-xl-5">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-header bg-transparent border-bottom p-3 d-flex justify-content-between align-items-center flex-wrap gap-2">
					<div class="d-flex align-items-center gap-2">
						<h5 class="fw-bold mb-0"><i class="ti tabler-activity me-2 text-danger"></i><?= htmlspecialchars($language::get('firewall_tab_live_threats', 'Live SOC Threat Stream')); ?></h5>
					</div>
					<div class="d-flex gap-2">
						<button type="button" class="btn btn-sm btn-outline-primary" onclick="fwRefreshLiveMonitor()">
							<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_refresh_feed', 'Refresh')); ?>
						</button>
					</div>
				</div>

				<div class="card-body p-3">
					<ul class="nav nav-tabs nav-fill mb-3" role="tablist">
						<li class="nav-item">
							<button class="nav-link active py-2 fw-bold" data-bs-toggle="tab" data-bs-target="#streamFail2ban" type="button" role="tab">
								<i class="ti tabler-terminal me-1 text-success"></i>fail2ban-server.log
							</button>
						</li>
						<li class="nav-item">
							<button class="nav-link py-2 fw-bold" data-bs-toggle="tab" data-bs-target="#streamSecurity" type="button" role="tab">
								<i class="ti tabler-shield-alert me-1 text-warning"></i>security.log (XC_VM)
							</button>
						</li>
					</ul>

					<div class="tab-content p-0">
						<div class="tab-pane fade show active" id="streamFail2ban" role="tabpanel">
							<div class="card border bg-dark text-white shadow-none">
								<div class="card-header bg-transparent border-bottom border-secondary d-flex justify-content-between align-items-center py-2 px-3">
									<span class="font-monospace small text-success"><i class="ti tabler-terminal me-1"></i>Daemon Feed</span>
									<span class="badge bg-success-subtle text-success small font-monospace">LIVE</span>
								</div>
								<div class="card-body p-3">
									<pre id="preFail2banFeed" class="text-light mb-0 fw-terminal-feed small"><?php
									if (!empty($fail2banFeed)) {
										echo htmlspecialchars(implode("\n", $fail2banFeed));
									} else {
										echo htmlspecialchars($language::get('firewall_feed_empty', 'No recent events recorded.'));
									}
									?></pre>
								</div>
							</div>
						</div>

						<div class="tab-pane fade" id="streamSecurity" role="tabpanel">
							<div class="card border bg-dark text-white shadow-none">
								<div class="card-header bg-transparent border-bottom border-secondary d-flex justify-content-between align-items-center py-2 px-3">
									<span class="font-monospace small text-warning"><i class="ti tabler-shield-alert me-1"></i>Application Alerts</span>
									<span class="badge bg-warning-subtle text-warning small font-monospace">ALERTS</span>
								</div>
								<div class="card-body p-3">
									<pre id="preSecurityFeed" class="text-light mb-0 fw-terminal-feed small"><?php
									if (!empty($securityFeed) && !empty($securityFeed[0])) {
										echo htmlspecialchars(implode("\n", $securityFeed));
									} else {
										echo htmlspecialchars($language::get('firewall_feed_empty', 'No recent events recorded.'));
									}
									?></pre>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>

	<!-- Recent Security Audit History Table -->
	<?php if (!empty($history)): ?>
		<div class="card border-0 shadow-sm mb-4">
			<div class="card-header bg-transparent p-3 border-bottom d-flex justify-content-between align-items-center">
				<h5 class="fw-bold mb-0"><i class="ti tabler-history me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_history_title', 'Recent Security Action Audit History')); ?></h5>
				<span class="badge bg-label-primary"><?= count($history); ?> <?= htmlspecialchars($language::get('records', 'Records')); ?></span>
			</div>
			<div class="table-responsive">
				<table class="table table-hover align-middle mb-0 font-monospace" id="historyTable">
					<thead class="table-light">
						<tr>
							<th><?= htmlspecialchars($language::get('firewall_col_datetime', 'Date & Time')); ?></th>
							<th><?= htmlspecialchars($language::get('firewall_col_ip', 'IP Address')); ?></th>
							<th><?= htmlspecialchars($language::get('firewall_col_jail', 'Jail')); ?></th>
							<th><?= htmlspecialchars($language::get('firewall_col_operation', 'Operation')); ?></th>
							<th><?= htmlspecialchars($language::get('firewall_col_reason', 'Reason / Trigger')); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($history as $h): ?>
							<tr>
								<td class="text-muted small"><?= date('Y-m-d H:i:s', (int) $h['date']); ?></td>
								<td class="fw-bold"><?= htmlspecialchars($h['ip']); ?></td>
								<td><span class="badge bg-label-secondary"><?= htmlspecialchars($h['jail']); ?></span></td>
								<td>
									<?php if ($h['action'] === 'BAN'): ?>
										<span class="badge bg-label-danger">BAN</span>
									<?php else: ?>
										<span class="badge bg-label-success">UNBAN</span>
									<?php endif; ?>
								</td>
								<td class="text-muted small"><?= htmlspecialchars($h['reason'] ?? '—'); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
	<?php endif; ?>

	<!-- Terminal CLI Command Reference Card -->
	<div class="card border-0 shadow-sm mb-4">
		<div class="card-header bg-transparent p-3 border-bottom">
			<h5 class="fw-bold mb-0"><i class="ti tabler-terminal-2 me-2 text-info"></i><?= htmlspecialchars($language::get('firewall_cli_reference_title', 'Terminal & CLI Command Reference')); ?></h5>
			<small class="text-muted"><?= htmlspecialchars($language::get('firewall_cli_reference_desc', 'Quick copy commands for administrative server maintenance')); ?></small>
		</div>

		<div class="table-responsive">
			<table class="table table-hover align-middle mb-0" id="cliTable">
				<thead class="table-light">
					<tr>
						<th class="fw-col-w25"><?= htmlspecialchars($language::get('firewall_col_operation', 'Operation')); ?></th>
						<th class="fw-col-w60">Command (Bash / Terminal)</th>
						<th class="no-sort text-end fw-col-w15"><?= htmlspecialchars($language::get('firewall_col_actions', 'Action')); ?></th>
					</tr>
				</thead>
				<tbody class="font-monospace small">
					<tr>
						<td class="fw-bold text-dark font-sans">Check Service Status</td>
						<td><code>sudo fail2ban-client status</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('sudo fail2ban-client status', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Check Panel Jail Status</td>
						<td><code>sudo fail2ban-client status xcvm-panel</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('sudo fail2ban-client status xcvm-panel', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Check Stream Jail Status</td>
						<td><code>sudo fail2ban-client status xcvm-stream</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('sudo fail2ban-client status xcvm-stream', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Check SSH Jail Status</td>
						<td><code>sudo fail2ban-client status sshd</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('sudo fail2ban-client status sshd', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Sync Active Bans to DB</td>
						<td><code>php /home/xc_vm/console.php firewall:sync</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('php /home/xc_vm/console.php firewall:sync', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Firewall Status Console</td>
						<td><code>php /home/xc_vm/console.php firewall status</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('php /home/xc_vm/console.php firewall status', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
					<tr>
						<td class="fw-bold text-dark font-sans">Tail Live Security Log</td>
						<td><code>tail -f /var/log/xcvm/security.log</code></td>
						<td class="text-end">
							<button type="button" class="btn btn-sm btn-outline-secondary" onclick="fwCopyCmd('tail -f /var/log/xcvm/security.log', this)">
								<i class="ti tabler-copy me-1"></i><?= htmlspecialchars($language::get('firewall_click_to_copy', 'Copy')); ?>
							</button>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>

</div>

<!-- Modal: Manual Ban -->
<div class="modal fade" id="modalManualBan" tabindex="-1" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title fw-bold"><i class="ti tabler-ban me-2 text-danger"></i><?= htmlspecialchars($language::get('firewall_modal_ban_title', 'Manual IP Ban Enforcement')); ?></h5>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
			</div>
			<form id="formManualBan" onsubmit="fwSubmitManualBan(event)">
				<div class="modal-body">
					<div class="mb-3">
						<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_modal_ip_label', 'IP Address to Ban')); ?></label>
						<input type="text" name="ip" class="form-control font-monospace" placeholder="e.g. 198.51.100.45" required>
					</div>
					<div class="mb-3">
						<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_modal_jail_label', 'Enforcement Jail / Rule')); ?></label>
						<select name="jail" class="form-select">
							<?php foreach ($rules as $r): ?>
								<option value="<?= htmlspecialchars($r['rule_key']); ?>"><?= htmlspecialchars($r['rule_key']); ?> (<?= htmlspecialchars($r['name']); ?>)</option>
							<?php endforeach; ?>
						</select>
					</div>
					<div class="mb-3">
						<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_modal_reason_label', 'Audit Reason')); ?></label>
						<input type="text" name="reason" class="form-control" value="Manual ban from Admin Panel">
					</div>
				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= htmlspecialchars($language::get('firewall_cancel', 'Cancel')); ?></button>
					<button type="submit" class="btn btn-danger"><?= htmlspecialchars($language::get('firewall_modal_confirm_ban', 'Enforce Ban')); ?></button>
				</div>
			</form>
		</div>
	</div>
</div>
