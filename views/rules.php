<?php
use XcVm\Module\Firewall\FirewallTranslator;

/** @var array $rules */
/** @var array $status */

$language       = FirewallTranslator::class;
$jails          = $status['jails'] ?? [];
$defaultCount   = count(array_filter($rules, fn($r) => ($r['category'] ?? '') === 'default'));
$customCount    = count(array_filter($rules, fn($r) => ($r['category'] ?? '') === 'custom'));
$activeCount    = count(array_filter($rules, fn($r) => !empty($r['enabled'])));
?>

<div class="container-xxl flex-grow-1 container-p-y">

	<!-- Header Bar -->
	<div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
		<div>
			<h4 class="fw-bold mb-1"><i class="ti tabler-list-check me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_rules_title', 'Firewall & Security Rules')); ?></h4>
			<p class="text-muted mb-0"><?= htmlspecialchars($language::get('firewall_rules_desc', 'Configure core system security jails, sensitivity thresholds, and manage custom Fail2ban rules.')); ?></p>
		</div>
		<div class="d-flex gap-2 flex-wrap">
			<a href="firewall" class="btn btn-outline-secondary">
				<i class="ti tabler-arrow-left me-1"></i><?= htmlspecialchars($language::get('firewall_back_to_dashboard', 'Back to Dashboard')); ?>
			</a>
			<button type="button" class="btn btn-outline-warning" onclick="fwResetDefaultRules()">
				<i class="ti tabler-history me-1"></i><?= htmlspecialchars($language::get('firewall_reset_default_rules', 'Reset Defaults')); ?>
			</button>
			<button type="button" class="btn btn-outline-info" onclick="fwDeploy()">
				<i class="ti tabler-reload me-1"></i><?= htmlspecialchars($language::get('firewall_deploy_now', 'Deploy & Reload')); ?>
			</button>
			<button type="button" class="btn btn-primary" onclick="fwOpenAddRuleModal()">
				<i class="ti tabler-plus me-1"></i><?= htmlspecialchars($language::get('firewall_add_rule', 'Create New Rule')); ?>
			</button>
		</div>
	</div>

	<!-- Quick Stat Cards — Formatted identically to reference design system -->
	<div class="row g-3 mb-4">
		<div class="col-sm-6 col-lg-3">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-primary rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-shield-lock fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_total_rules', 'Total Defined Rules')); ?></small>
						<h4 class="mb-0 fw-bold"><?= count($rules); ?></h4>
					</div>
				</div>
			</div>
		</div>

		<div class="col-sm-6 col-lg-3">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-info rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-cpu fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_core_rules', 'Core Default Rules')); ?></small>
						<h4 class="mb-0 fw-bold"><?= $defaultCount; ?></h4>
					</div>
				</div>
			</div>
		</div>

		<div class="col-sm-6 col-lg-3">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-warning rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-puzzle fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_custom_rules', 'Custom Rules')); ?></small>
						<h4 class="mb-0 fw-bold"><?= $customCount; ?></h4>
					</div>
				</div>
			</div>
		</div>

		<div class="col-sm-6 col-lg-3">
			<div class="card border-0 shadow-sm h-100">
				<div class="card-body d-flex align-items-center p-3">
					<div class="avatar avatar-md bg-label-success rounded-circle me-3 d-flex align-items-center justify-content-center flex-shrink-0">
						<i class="ti tabler-circle-check fs-3"></i>
					</div>
					<div>
						<small class="text-muted d-block fw-semibold"><?= htmlspecialchars($language::get('firewall_active_enforced', 'Active Enforced')); ?></small>
						<h4 class="mb-0 fw-bold text-success"><?= $activeCount; ?></h4>
					</div>
				</div>
			</div>
		</div>
	</div>

	<!-- Rules Table Card -->
	<div class="card border-0 shadow-sm mb-4">
		<div class="card-header bg-transparent d-flex flex-wrap justify-content-between align-items-center p-3 gap-2 border-bottom">
			<div class="d-flex align-items-center gap-2">
				<ul class="nav nav-pills" id="ruleCategoryFilter" role="tablist">
					<li class="nav-item">
						<button class="nav-link active py-1 px-3 fw-semibold" type="button" onclick="fwFilterRules('all')"><?= htmlspecialchars($language::get('all', 'All')); ?></button>
					</li>
					<li class="nav-item">
						<button class="nav-link py-1 px-3 fw-semibold" type="button" onclick="fwFilterRules('default')"><?= htmlspecialchars($language::get('firewall_filter_core', 'Core Defaults')); ?></button>
					</li>
					<li class="nav-item">
						<button class="nav-link py-1 px-3 fw-semibold" type="button" onclick="fwFilterRules('custom')"><?= htmlspecialchars($language::get('firewall_filter_custom', 'Custom')); ?></button>
					</li>
				</ul>
			</div>

			<div class="d-flex gap-2">
				<input type="text" id="filterRulesInput" class="form-control form-control-sm fw-search-input" placeholder="<?= htmlspecialchars($language::get('firewall_search_rules', 'Search rules...')); ?>">
			</div>
		</div>

		<div class="table-responsive">
			<table class="table table-hover align-middle mb-0" id="rulesTable">
				<thead class="table-light">
					<tr>
						<th class="fw-col-w25"><?= htmlspecialchars($language::get('firewall_col_rule_name', 'Rule Key & Name')); ?></th>
						<th class="fw-col-w10"><?= htmlspecialchars($language::get('firewall_col_category', 'Category')); ?></th>
						<th class="fw-col-w15"><?= htmlspecialchars($language::get('firewall_col_ports', 'Ports / Protocol')); ?></th>
						<th class="fw-col-w20"><?= htmlspecialchars($language::get('firewall_col_thresholds', 'Thresholds')); ?></th>
						<th class="no-sort fw-col-w10"><?= htmlspecialchars($language::get('firewall_col_status', 'Status')); ?></th>
						<th class="no-sort text-end fw-col-w20"><?= htmlspecialchars($language::get('firewall_col_actions', 'Actions')); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ($rules as $r): ?>
						<?php
						$ruleKey    = $r['rule_key'];
						$category   = $r['category'] ?? 'custom';
						$isEnabled  = !empty($r['enabled']);
						$port       = (string) ($r['port'] ?? 'all');
						$proto      = (string) ($r['protocol'] ?? 'tcp');
						$maxretry   = (int) ($r['maxretry'] ?? 5);
						$findtime   = (int) ($r['findtime'] ?? 600);
						$bantime    = (int) ($r['bantime'] ?? 3600);
						$logPath    = (string) ($r['log_path'] ?? '');
						$regex      = (string) ($r['filter_regex'] ?? '');
						?>
						<tr class="rule-row" data-category="<?= htmlspecialchars($category); ?>">
							<td>
								<div class="d-flex align-items-center gap-2">
									<div class="avatar avatar-sm bg-label-primary rounded-circle d-flex align-items-center justify-content-center flex-shrink-0">
										<i class="ti tabler-shield fs-5"></i>
									</div>
									<div>
										<span class="fw-bold text-dark font-monospace d-block"><?= htmlspecialchars($ruleKey); ?></span>
										<small class="text-muted d-block"><?= htmlspecialchars($r['name'] ?? $ruleKey); ?></small>
									</div>
								</div>
							</td>
							<td>
								<?php if ($category === 'default'): ?>
									<span class="badge fw-badge-category-default font-monospace"><?= htmlspecialchars($language::get('core_default', 'Core')); ?></span>
								<?php else: ?>
									<span class="badge fw-badge-category-custom font-monospace"><?= htmlspecialchars($language::get('custom', 'Custom')); ?></span>
								<?php endif; ?>
							</td>
							<td>
								<div class="font-monospace small">
									<span class="badge bg-label-secondary"><?= htmlspecialchars($port); ?></span>
									<span class="text-muted text-uppercase ms-1"><?= htmlspecialchars($proto); ?></span>
								</div>
							</td>
							<td>
								<div class="font-monospace small">
									<span title="Max Retries"><i class="ti tabler-rotate me-1 text-muted"></i><?= $maxretry; ?> retries</span> /
									<span title="Find Window"><i class="ti tabler-clock me-1 text-muted"></i><?= $findtime; ?>s</span>
									<span class="d-block text-danger mt-1"><i class="ti tabler-ban me-1"></i><?= $bantime; ?>s ban</span>
								</div>
							</td>
							<td>
								<div class="form-check form-switch m-0">
									<input class="form-check-input" type="checkbox" role="switch" <?= $isEnabled ? 'checked' : ''; ?> onchange="fwToggleRule('<?= htmlspecialchars($ruleKey); ?>', this)">
								</div>
							</td>
							<td class="text-end">
								<div class="d-flex justify-content-end gap-1">
									<?php if (!empty($regex)): ?>
										<button type="button" class="btn btn-sm btn-outline-info" title="Test Regex" onclick="fwOpenTestRegexModal('<?= htmlspecialchars(addslashes($regex)); ?>')">
											<i class="ti tabler-check"></i>
										</button>
									<?php endif; ?>

									<button type="button" class="btn btn-sm btn-outline-primary" title="Edit Rule" onclick='fwOpenEditRuleModal(<?= json_encode($r); ?>)'>
										<i class="ti tabler-edit"></i>
									</button>

									<?php if ($category === 'custom'): ?>
										<button type="button" class="btn btn-sm btn-outline-danger" title="Delete Rule" onclick="fwDeleteRule('<?= htmlspecialchars($ruleKey); ?>')">
											<i class="ti tabler-trash"></i>
										</button>
									<?php endif; ?>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>

</div>

<!-- Modal: Create / Edit Rule -->
<div class="modal fade" id="modalRuleEditor" tabindex="-1" aria-hidden="true">
	<div class="modal-dialog modal-lg modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title fw-bold" id="modalRuleTitle">
					<i class="ti tabler-plus me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_add_rule', 'Create New Security Rule')); ?>
				</h5>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
			</div>
			<form id="formRuleEditor" onsubmit="fwSubmitRuleForm(event)">
				<div class="modal-body">
					<input type="hidden" name="category" id="ruleInputCategory" value="custom">

					<div class="row g-3 mb-3">
						<div class="col-md-6">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_rule_key', 'Rule Identifier (Key)')); ?></label>
							<input type="text" name="rule_key" id="ruleInputKey" class="form-control font-monospace" placeholder="e.g. xcvm-custom-app" required>
							<small class="text-muted d-block mt-1">Unique alphanumeric identifier with dashes or underscores.</small>
						</div>
						<div class="col-md-6">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_rule_name', 'Rule Display Name')); ?></label>
							<input type="text" name="name" id="ruleInputName" class="form-control" placeholder="e.g. Custom Web Protection" required>
						</div>
					</div>

					<div class="row g-3 mb-3">
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_port', 'Target Ports')); ?></label>
							<input type="text" name="port" id="ruleInputPort" class="form-control font-monospace" placeholder="e.g. 80,443 or all" value="80,443" required>
						</div>
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_protocol', 'Protocol')); ?></label>
							<select name="protocol" id="ruleInputProtocol" class="form-select">
								<option value="tcp">TCP</option>
								<option value="udp">UDP</option>
								<option value="all">ALL Protocols</option>
							</select>
						</div>
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_action_type', 'Firewall Action')); ?></label>
							<select name="action_type" id="ruleInputActionType" class="form-select">
								<option value="iptables-multiport">iptables-multiport</option>
								<option value="iptables-allports">iptables-allports</option>
								<option value="nftables">nftables</option>
							</select>
						</div>
					</div>

					<div class="row g-3 mb-3">
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_maxretry', 'Max Retry')); ?></label>
							<input type="number" name="maxretry" id="ruleInputMaxretry" class="form-control" min="1" max="1000" value="5" required>
							<small class="text-muted">Failures before ban.</small>
						</div>
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_findtime', 'Find Window (Seconds)')); ?></label>
							<input type="number" name="findtime" id="ruleInputFindtime" class="form-control" min="10" max="604800" value="600" required>
							<small class="text-muted">Detection timeframe.</small>
						</div>
						<div class="col-md-4">
							<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_bantime', 'Ban Time (Seconds)')); ?></label>
							<input type="number" name="bantime" id="ruleInputBantime" class="form-control" min="30" max="31536000" value="3600" required>
							<small class="text-muted">Block duration.</small>
						</div>
					</div>

					<div class="mb-3">
						<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_log_path', 'Log File Path')); ?></label>
						<input type="text" name="log_path" id="ruleInputLogPath" class="form-control font-monospace" placeholder="/var/log/xcvm/security.log" value="/var/log/xcvm/security.log" required>
						<small class="text-muted">The server log file monitored by Fail2ban.</small>
					</div>

					<div class="mb-3">
						<div class="d-flex justify-content-between align-items-center mb-1">
							<label class="form-label fw-bold mb-0"><?= htmlspecialchars($language::get('firewall_label_filter_regex', 'Fail2ban Filter Regex (failregex)')); ?></label>
							<button type="button" class="btn btn-sm btn-link p-0 text-primary" onclick="fwOpenTestRegexWithCurrent()">
								<i class="ti tabler-flask me-1"></i>Test Regex
							</button>
						</div>
						<textarea name="filter_regex" id="ruleInputFilterRegex" class="form-control font-monospace" rows="3" placeholder="^.*\[app-name\]\s+<HOST>\s+-\s+Authentication failure.*$"></textarea>
						<small class="text-muted d-block mt-1">Use <code>&lt;HOST&gt;</code> tag to match attacker IP addresses.</small>
					</div>

					<div class="mb-3">
						<label class="form-label fw-bold"><?= htmlspecialchars($language::get('firewall_label_desc', 'Rule Description')); ?></label>
						<textarea name="description" id="ruleInputDescription" class="form-control" rows="2" placeholder="Describe the purpose of this rule..."></textarea>
					</div>

					<div class="form-check form-switch">
						<input class="form-check-input" type="checkbox" name="enabled" id="ruleInputEnabled" value="1" checked>
						<label class="form-check-label fw-bold" for="ruleInputEnabled"><?= htmlspecialchars($language::get('firewall_enable_rule_now', 'Enable and activate this rule immediately')); ?></label>
					</div>
				</div>

				<div class="modal-footer">
					<button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= htmlspecialchars($language::get('cancel', 'Cancel')); ?></button>
					<button type="submit" class="btn btn-primary" id="btnSaveRuleSubmit"><?= htmlspecialchars($language::get('save_changes', 'Save Rule')); ?></button>
				</div>
			</form>
		</div>
	</div>
</div>

<!-- Modal: Regex Tester -->
<div class="modal fade" id="modalRegexTester" tabindex="-1" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h5 class="modal-title fw-bold">
					<i class="ti tabler-flask me-2 text-info"></i><?= htmlspecialchars($language::get('firewall_test_regex_title', 'Fail2ban Regex Validator')); ?>
				</h5>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
			</div>
			<div class="modal-body">
				<div class="mb-3">
					<label class="form-label fw-bold">Regex Pattern</label>
					<input type="text" id="regexTesterInput" class="form-control font-monospace" placeholder="^.*<HOST>.*$">
				</div>
				<div class="mb-3">
					<label class="form-label fw-bold">Sample Log Line</label>
					<textarea id="regexTesterSample" class="form-control font-monospace" rows="3" placeholder="2026-10-13 12:00:00 [xcvm-panel] 192.168.1.50 - Failed login for admin"></textarea>
				</div>
				<button type="button" class="btn btn-info w-100 mb-3" onclick="fwExecuteRegexTest()">
					<i class="ti tabler-check me-1"></i>Validate & Test Regex
				</button>
				<div id="regexTesterOutput" class="p-3 border rounded fw-regex-test-box bg-light text-muted small">
					Click test to see validation results and extracted IP.
				</div>
			</div>
		</div>
	</div>
</div>
