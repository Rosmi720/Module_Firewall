<?php
use XcVm\Module\Firewall\FirewallTranslator;

/** @var array $securityLogs */
/** @var array $fail2banLogs */

$language = FirewallTranslator::class;
?>

<div class="container-xxl flex-grow-1 container-p-y">

	<div class="d-flex align-items-center justify-content-between mb-4 flex-wrap gap-2">
		<div>
			<h4 class="fw-bold mb-1"><i class="ti tabler-file-text me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_logs_title', 'Live Security & Fail2ban Logs')); ?></h4>
			<p class="text-muted mb-0"><?= htmlspecialchars($language::get('firewall_logs_desc', 'Real-time telemetry feeds for application intrusion alerts and Fail2ban daemon activity.')); ?></p>
		</div>
		<div class="d-flex gap-2 flex-wrap">
			<a href="firewall" class="btn btn-outline-secondary">
				<i class="ti tabler-arrow-left me-1"></i><?= htmlspecialchars($language::get('firewall_back_to_dashboard', 'Dashboard')); ?>
			</a>
			<a href="firewall_rules" class="btn btn-outline-primary">
				<i class="ti tabler-list-check me-1"></i><?= htmlspecialchars($language::get('firewall_nav_rules', 'Rules')); ?>
			</a>
			<a href="firewall_settings" class="btn btn-outline-info">
				<i class="ti tabler-settings me-1"></i><?= htmlspecialchars($language::get('firewall_settings', 'Settings')); ?>
			</a>
			<button type="button" class="btn btn-primary" onclick="fwRefreshCurrentLogs()">
				<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_refresh_logs', 'Refresh')); ?>
			</button>
		</div>
	</div>

	<!-- Nav Tabs -->
	<ul class="nav nav-tabs nav-fill mb-3" role="tablist">
		<li class="nav-item">
			<button type="button" class="nav-link active fw-bold" role="tab" data-bs-toggle="tab" data-bs-target="#tabSecurityLog" aria-selected="true" onclick="fwActiveLogType='security'">
				<i class="ti tabler-shield-alert me-1 text-danger"></i><?= htmlspecialchars($language::get('firewall_tab_security_log', 'XC_VM Application Security Feed (security.log)')); ?>
			</button>
		</li>
		<li class="nav-item">
			<button type="button" class="nav-link fw-bold" role="tab" data-bs-toggle="tab" data-bs-target="#tabFail2banLog" aria-selected="false" onclick="fwActiveLogType='fail2ban'">
				<i class="ti tabler-cpu me-1 text-info"></i><?= htmlspecialchars($language::get('firewall_tab_fail2ban_log', 'Fail2ban Server Daemon Log (fail2ban.log)')); ?>
			</button>
		</li>
	</ul>

	<!-- Tab Content (Zero Inline Styles) -->
	<div class="tab-content p-0 border-0">

		<!-- Tab: Security Log -->
		<div class="tab-pane fade show active" id="tabSecurityLog" role="tabpanel">
			<div class="card border-0 shadow-sm bg-dark text-light">
				<div class="card-header bg-dark border-bottom border-secondary d-flex justify-content-between align-items-center p-3">
					<div class="d-flex align-items-center gap-2">
						<span class="badge bg-danger">XC_VM Security Feed</span>
						<small class="text-secondary"><?= htmlspecialchars($language::get('firewall_last_100_lines', 'Last 100 Log Lines')); ?></small>
					</div>
					<button class="btn btn-sm btn-outline-light" onclick="fwRefreshCurrentLogs()">
						<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_refresh_logs', 'Refresh')); ?>
					</button>
				</div>
				<div class="card-body p-3">
					<pre id="preSecurityLogs" class="mb-0 text-light fw-terminal-logs small"><?php
					if (!empty($securityLogs)) {
						foreach ($securityLogs as $line) {
							echo htmlspecialchars($line) . "\n";
						}
					} else {
						echo htmlspecialchars($language::get('firewall_no_logs', 'No logs recorded.')) . "\n";
					}
					?></pre>
				</div>
			</div>
		</div>

		<!-- Tab: Fail2ban Log -->
		<div class="tab-pane fade" id="tabFail2banLog" role="tabpanel">
			<div class="card border-0 shadow-sm bg-dark text-light">
				<div class="card-header bg-dark border-bottom border-secondary d-flex justify-content-between align-items-center p-3">
					<div class="d-flex align-items-center gap-2">
						<span class="badge bg-info">Fail2ban Daemon Log</span>
						<small class="text-secondary"><?= htmlspecialchars($language::get('firewall_last_100_lines', 'Last 100 Log Lines')); ?></small>
					</div>
					<button class="btn btn-sm btn-outline-light" onclick="fwRefreshCurrentLogs()">
						<i class="ti tabler-refresh me-1"></i><?= htmlspecialchars($language::get('firewall_refresh_logs', 'Refresh')); ?>
					</button>
				</div>
				<div class="card-body p-3">
					<pre id="preFail2banLogs" class="mb-0 text-light fw-terminal-logs small"><?php
					if (!empty($fail2banLogs)) {
						foreach ($fail2banLogs as $line) {
							echo htmlspecialchars($line) . "\n";
						}
					} else {
						echo htmlspecialchars($language::get('firewall_no_logs', 'No logs recorded.')) . "\n";
					}
					?></pre>
				</div>
			</div>
		</div>

	</div>

</div>
