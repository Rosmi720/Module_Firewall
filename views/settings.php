<?php
use XcVm\Module\Firewall\FirewallTranslator;

/** @var array $settings */
/** @var array $status */

$language = FirewallTranslator::class;
$jails    = $settings['jails'] ?? [];
$preset   = $settings['preset'] ?? 'balanced';
$ignoreip = $settings['ignoreip'] ?? '';
$syncToDb = !empty($settings['sync_to_db']);
?>

<div class="container-xxl flex-grow-1 container-p-y">

	<div class="d-flex align-items-center justify-content-between mb-4">
		<div>
			<h4 class="fw-bold mb-1"><i class="ti tabler-adjustments-alt me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_settings_title')); ?></h4>
			<p class="text-muted mb-0"><?= htmlspecialchars($language::get('firewall_settings_desc')); ?></p>
		</div>
		<div class="d-flex gap-2 flex-wrap">
			<a href="firewall" class="btn btn-outline-secondary">
				<i class="ti tabler-arrow-left me-1"></i><?= htmlspecialchars($language::get('firewall_back_to_dashboard', 'Dashboard')); ?>
			</a>
			<a href="firewall_rules" class="btn btn-outline-primary">
				<i class="ti tabler-list-check me-1"></i><?= htmlspecialchars($language::get('firewall_nav_rules', 'Rules')); ?>
			</a>
			<a href="firewall_logs" class="btn btn-outline-info">
				<i class="ti tabler-file-text me-1"></i><?= htmlspecialchars($language::get('firewall_live_logs', 'Logs')); ?>
			</a>
			<button type="button" class="btn btn-primary" onclick="fwSaveSettingsForm()">
				<i class="ti tabler-device-floppy me-1"></i><?= htmlspecialchars($language::get('firewall_save_settings', 'Save Settings')); ?>
			</button>
		</div>

	</div>

	<form id="formFirewallSettings" onsubmit="fwSaveSettingsForm(event)">

		<!-- Presets Card -->
		<div class="card border-0 shadow-sm mb-4">
			<div class="card-body p-4">
				<div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
					<div>
						<h5 class="fw-bold mb-1"><i class="ti tabler-wand me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_presets_title')); ?></h5>
						<p class="text-muted small mb-0"><?= htmlspecialchars($language::get('firewall_presets_desc')); ?></p>
					</div>
					<span class="badge bg-label-primary rounded-pill px-3 py-1 font-monospace">
						<i class="ti tabler-bolt me-1"></i>1-Click Tuning
					</span>
				</div>

				<div class="row g-3">
					<!-- Preset 1: Balanced (Recommended) -->
					<div class="col-12 col-sm-6 col-xl-3">
						<div class="card h-100 p-3 fw-preset-card <?= $preset === 'balanced' ? 'active' : ''; ?>" id="cardPreset_balanced" onclick="fwSelectPreset('balanced')">
							<div class="d-flex justify-content-between align-items-start mb-2">
								<div class="avatar avatar-md bg-label-success rounded d-flex align-items-center justify-content-center">
									<i class="ti tabler-scale fs-3"></i>
								</div>
								<div class="d-flex align-items-center gap-2">
									<span class="badge bg-label-success rounded-pill"><?= htmlspecialchars($language::get('firewall_preset_badge_recommended', 'Recommended')); ?></span>
									<input class="form-check-input mt-0" type="radio" name="preset" id="preset_balanced" value="balanced" <?= $preset === 'balanced' ? 'checked' : ''; ?>>
								</div>
							</div>
							<h6 class="fw-bold mb-1 text-dark"><?= htmlspecialchars($language::get('firewall_preset_balanced')); ?></h6>
							<p class="text-muted small mb-3 flex-grow-1"><?= htmlspecialchars($language::get('firewall_preset_balanced_desc')); ?></p>

							<div class="fw-preset-specs p-2 border">
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_retries', 'Retries')); ?>:</span>
									<span class="badge bg-label-secondary font-monospace">5 - 10</span>
								</div>
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_window', 'Window')); ?>:</span>
									<span class="badge bg-label-secondary font-monospace">5m - 10m</span>
								</div>
								<div class="d-flex justify-content-between align-items-center">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_ban', 'Ban Duration')); ?>:</span>
									<span class="badge bg-label-success font-monospace">1h - 24h</span>
								</div>
							</div>
						</div>
					</div>

					<!-- Preset 2: Strict Security -->
					<div class="col-12 col-sm-6 col-xl-3">
						<div class="card h-100 p-3 fw-preset-card <?= $preset === 'strict' ? 'active' : ''; ?>" id="cardPreset_strict" onclick="fwSelectPreset('strict')">
							<div class="d-flex justify-content-between align-items-start mb-2">
								<div class="avatar avatar-md bg-label-primary rounded d-flex align-items-center justify-content-center">
									<i class="ti tabler-shield-lock fs-3"></i>
								</div>
								<div class="d-flex align-items-center gap-2">
									<span class="badge bg-label-primary rounded-pill"><?= htmlspecialchars($language::get('firewall_preset_badge_strict', 'High Security')); ?></span>
									<input class="form-check-input mt-0" type="radio" name="preset" id="preset_strict" value="strict" <?= $preset === 'strict' ? 'checked' : ''; ?>>
								</div>
							</div>
							<h6 class="fw-bold mb-1 text-dark"><?= htmlspecialchars($language::get('firewall_preset_strict')); ?></h6>
							<p class="text-muted small mb-3 flex-grow-1"><?= htmlspecialchars($language::get('firewall_preset_strict_desc')); ?></p>

							<div class="fw-preset-specs p-2 border">
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_retries', 'Retries')); ?>:</span>
									<span class="badge bg-label-secondary font-monospace">3 - 5</span>
								</div>
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_window', 'Window')); ?>:</span>
									<span class="badge bg-label-secondary font-monospace">10m</span>
								</div>
								<div class="d-flex justify-content-between align-items-center">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_ban', 'Ban Duration')); ?>:</span>
									<span class="badge bg-label-primary font-monospace">24h - 72h</span>
								</div>
							</div>
						</div>
					</div>

					<!-- Preset 3: Aggressive DDoS Lockdown -->
					<div class="col-12 col-sm-6 col-xl-3">
						<div class="card h-100 p-3 fw-preset-card <?= $preset === 'aggressive' ? 'active' : ''; ?>" id="cardPreset_aggressive" onclick="fwSelectPreset('aggressive')">
							<div class="d-flex justify-content-between align-items-start mb-2">
								<div class="avatar avatar-md bg-label-danger rounded d-flex align-items-center justify-content-center">
									<i class="ti tabler-flame fs-3"></i>
								</div>
								<div class="d-flex align-items-center gap-2">
									<span class="badge bg-label-danger rounded-pill"><?= htmlspecialchars($language::get('firewall_preset_badge_aggressive', 'Emergency DDoS')); ?></span>
									<input class="form-check-input mt-0" type="radio" name="preset" id="preset_aggressive" value="aggressive" <?= $preset === 'aggressive' ? 'checked' : ''; ?>>
								</div>
							</div>
							<h6 class="fw-bold mb-1 text-dark"><?= htmlspecialchars($language::get('firewall_preset_aggressive')); ?></h6>
							<p class="text-muted small mb-3 flex-grow-1"><?= htmlspecialchars($language::get('firewall_preset_aggressive_desc')); ?></p>

							<div class="fw-preset-specs p-2 border">
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_retries', 'Retries')); ?>:</span>
									<span class="badge bg-label-danger font-monospace">2 - 3</span>
								</div>
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_window', 'Window')); ?>:</span>
									<span class="badge bg-label-secondary font-monospace">1m - 5m</span>
								</div>
								<div class="d-flex justify-content-between align-items-center">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_ban', 'Ban Duration')); ?>:</span>
									<span class="badge bg-label-danger font-monospace">24h - 7d</span>
								</div>
							</div>
						</div>
					</div>

					<!-- Preset 4: Custom Tuning -->
					<div class="col-12 col-sm-6 col-xl-3">
						<div class="card h-100 p-3 fw-preset-card <?= $preset === 'custom' ? 'active' : ''; ?>" id="cardPreset_custom" onclick="fwSelectPreset('custom')">
							<div class="d-flex justify-content-between align-items-start mb-2">
								<div class="avatar avatar-md bg-label-secondary rounded d-flex align-items-center justify-content-center">
									<i class="ti tabler-adjustments-alt fs-3"></i>
								</div>
								<div class="d-flex align-items-center gap-2">
									<span class="badge bg-label-secondary rounded-pill"><?= htmlspecialchars($language::get('firewall_preset_badge_custom', 'Manual Control')); ?></span>
									<input class="form-check-input mt-0" type="radio" name="preset" id="preset_custom" value="custom" <?= $preset === 'custom' ? 'checked' : ''; ?>>
								</div>
							</div>
							<h6 class="fw-bold mb-1 text-dark"><?= htmlspecialchars($language::get('firewall_preset_custom')); ?></h6>
							<p class="text-muted small mb-3 flex-grow-1"><?= htmlspecialchars($language::get('firewall_preset_custom_desc')); ?></p>

							<div class="fw-preset-specs p-2 border">
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_retries', 'Retries')); ?>:</span>
									<span class="badge bg-label-info font-monospace">Manual</span>
								</div>
								<div class="d-flex justify-content-between align-items-center mb-1">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_window', 'Window')); ?>:</span>
									<span class="badge bg-label-info font-monospace">Manual</span>
								</div>
								<div class="d-flex justify-content-between align-items-center">
									<span class="text-muted small"><?= htmlspecialchars($language::get('firewall_preset_spec_ban', 'Ban Duration')); ?>:</span>
									<span class="badge bg-label-info font-monospace">Manual</span>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- Whitelist Card -->
		<div class="card border-0 shadow-sm mb-4">
			<div class="card-body p-4">
				<h5 class="fw-bold mb-2"><i class="ti tabler-shield-check me-2 text-success"></i><?= htmlspecialchars($language::get('firewall_whitelist_title')); ?></h5>
				<p class="text-muted small mb-3"><?= htmlspecialchars($language::get('firewall_whitelist_desc')); ?></p>
				<textarea name="ignoreip" id="inputIgnoreIp" class="form-control font-monospace" rows="3" placeholder="127.0.0.1/8 ::1 192.168.1.1"><?= htmlspecialchars($ignoreip); ?></textarea>
				<small class="text-muted mt-1 d-block">
					<i class="ti tabler-info-circle me-1"></i><?= htmlspecialchars($language::get('firewall_whitelist_note')); ?>
				</small>
			</div>
		</div>

		<!-- Jails Configuration Cards -->
		<div class="row g-4 mb-4">

			<!-- Jail: sshd -->
			<div class="col-md-6">
				<div class="card border-0 shadow-sm h-100">
					<div class="card-header bg-light d-flex justify-content-between align-items-center p-3">
						<div class="d-flex align-items-center gap-2">
							<i class="ti tabler-terminal fs-4 text-info"></i>
							<h6 class="fw-bold mb-0"><?= htmlspecialchars($language::get('firewall_jail_sshd_title')); ?> (sshd)</h6>
						</div>
						<div class="form-check form-switch mb-0">
							<input class="form-check-input" type="checkbox" name="jails[sshd][enabled]" value="1" <?= !empty($jails['sshd']['enabled']) ? 'checked' : ''; ?>>
						</div>
					</div>
					<div class="card-body p-3">
						<div class="mb-3">
							<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_port')); ?></label>
							<input type="text" name="jails[sshd][port]" id="sshd_port" class="form-control form-control-sm font-monospace" value="<?= htmlspecialchars($jails['sshd']['port'] ?? 'ssh'); ?>">
						</div>
						<div class="row g-2">
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_maxretry')); ?></label>
								<input type="number" name="jails[sshd][maxretry]" id="sshd_maxretry" class="form-control form-control-sm" value="<?= (int) ($jails['sshd']['maxretry'] ?? 5); ?>" min="1">
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_findtime')); ?></label>
								<input type="number" name="jails[sshd][findtime]" id="sshd_findtime" class="form-control form-control-sm" value="<?= (int) ($jails['sshd']['findtime'] ?? 600); ?>" min="10">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_bantime')); ?></label>
								<input type="number" name="jails[sshd][bantime]" id="sshd_bantime" class="form-control form-control-sm" value="<?= (int) ($jails['sshd']['bantime'] ?? 86400); ?>" min="30">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Jail: xcvm-panel -->
			<div class="col-md-6">
				<div class="card border-0 shadow-sm h-100">
					<div class="card-header bg-light d-flex justify-content-between align-items-center p-3">
						<div class="d-flex align-items-center gap-2">
							<i class="ti tabler-user-shield fs-4 text-primary"></i>
							<h6 class="fw-bold mb-0"><?= htmlspecialchars($language::get('firewall_jail_panel_title')); ?> (xcvm-panel)</h6>
						</div>
						<div class="form-check form-switch mb-0">
							<input class="form-check-input" type="checkbox" name="jails[xcvm-panel][enabled]" value="1" <?= !empty($jails['xcvm-panel']['enabled']) ? 'checked' : ''; ?>>
						</div>
					</div>
					<div class="card-body p-3">
						<div class="mb-3">
							<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_port')); ?></label>
							<input type="text" name="jails[xcvm-panel][port]" id="panel_port" class="form-control form-control-sm font-monospace" value="<?= htmlspecialchars($jails['xcvm-panel']['port'] ?? 'http,https,80,443'); ?>">
						</div>
						<div class="row g-2">
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_maxretry')); ?></label>
								<input type="number" name="jails[xcvm-panel][maxretry]" id="panel_maxretry" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-panel']['maxretry'] ?? 5); ?>" min="1">
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_findtime')); ?></label>
								<input type="number" name="jails[xcvm-panel][findtime]" id="panel_findtime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-panel']['findtime'] ?? 600); ?>" min="10">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_bantime')); ?></label>
								<input type="number" name="jails[xcvm-panel][bantime]" id="panel_bantime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-panel']['bantime'] ?? 7200); ?>" min="30">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Jail: xcvm-stream -->
			<div class="col-md-6">
				<div class="card border-0 shadow-sm h-100">
					<div class="card-header bg-light d-flex justify-content-between align-items-center p-3">
						<div class="d-flex align-items-center gap-2">
							<i class="ti tabler-video fs-4 text-warning"></i>
							<h6 class="fw-bold mb-0"><?= htmlspecialchars($language::get('firewall_jail_stream_title')); ?> (xcvm-stream)</h6>
						</div>
						<div class="form-check form-switch mb-0">
							<input class="form-check-input" type="checkbox" name="jails[xcvm-stream][enabled]" value="1" <?= !empty($jails['xcvm-stream']['enabled']) ? 'checked' : ''; ?>>
						</div>
					</div>
					<div class="card-body p-3">
						<div class="mb-3">
							<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_port')); ?></label>
							<input type="text" name="jails[xcvm-stream][port]" id="stream_port" class="form-control form-control-sm font-monospace" value="<?= htmlspecialchars($jails['xcvm-stream']['port'] ?? 'http,https,80,443,8880,31210'); ?>">
						</div>
						<div class="row g-2">
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_maxretry')); ?></label>
								<input type="number" name="jails[xcvm-stream][maxretry]" id="stream_maxretry" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-stream']['maxretry'] ?? 10); ?>" min="1">
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_findtime')); ?></label>
								<input type="number" name="jails[xcvm-stream][findtime]" id="stream_findtime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-stream']['findtime'] ?? 300); ?>" min="10">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_bantime')); ?></label>
								<input type="number" name="jails[xcvm-stream][bantime]" id="stream_bantime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-stream']['bantime'] ?? 3600); ?>" min="30">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Jail: xcvm-flood -->
			<div class="col-md-6">
				<div class="card border-0 shadow-sm h-100">
					<div class="card-header bg-light d-flex justify-content-between align-items-center p-3">
						<div class="d-flex align-items-center gap-2">
							<i class="ti tabler-flame fs-4 text-danger"></i>
							<h6 class="fw-bold mb-0"><?= htmlspecialchars($language::get('firewall_jail_flood_title')); ?> (xcvm-flood)</h6>
						</div>
						<div class="form-check form-switch mb-0">
							<input class="form-check-input" type="checkbox" name="jails[xcvm-flood][enabled]" value="1" <?= !empty($jails['xcvm-flood']['enabled']) ? 'checked' : ''; ?>>
						</div>
					</div>
					<div class="card-body p-3">
						<div class="mb-3">
							<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_port')); ?></label>
							<input type="text" name="jails[xcvm-flood][port]" id="flood_port" class="form-control form-control-sm font-monospace" value="<?= htmlspecialchars($jails['xcvm-flood']['port'] ?? 'http,https,80,443'); ?>">
						</div>
						<div class="row g-2">
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_maxretry')); ?></label>
								<input type="number" name="jails[xcvm-flood][maxretry]" id="flood_maxretry" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-flood']['maxretry'] ?? 120); ?>" min="1">
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_findtime')); ?></label>
								<input type="number" name="jails[xcvm-flood][findtime]" id="flood_findtime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-flood']['findtime'] ?? 60); ?>" min="10">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
							<div class="col-4">
								<label class="form-label small fw-bold"><?= htmlspecialchars($language::get('firewall_label_bantime')); ?></label>
								<input type="number" name="jails[xcvm-flood][bantime]" id="flood_bantime" class="form-control form-control-sm" value="<?= (int) ($jails['xcvm-flood']['bantime'] ?? 1800); ?>" min="30">
								<small class="text-muted"><?= htmlspecialchars($language::get('firewall_seconds')); ?></small>
							</div>
						</div>
					</div>
				</div>
			</div>

		</div>

		<!-- Cluster & DB Sync Card -->
		<div class="card border-0 shadow-sm mb-4">
			<div class="card-body p-4 d-flex align-items-center justify-content-between">
				<div>
					<h6 class="fw-bold mb-1"><i class="ti tabler-refresh me-2 text-primary"></i><?= htmlspecialchars($language::get('firewall_sync_title')); ?></h6>
					<p class="text-muted small mb-0"><?= htmlspecialchars($language::get('firewall_sync_desc')); ?></p>
				</div>
				<div class="form-check form-switch fs-4">
					<input class="form-check-input" type="checkbox" name="sync_to_db" value="1" <?= $syncToDb ? 'checked' : ''; ?>>
				</div>
			</div>
		</div>

		<div class="d-flex justify-content-end gap-2">
			<a href="firewall" class="btn btn-outline-secondary"><?= htmlspecialchars($language::get('firewall_cancel')); ?></a>
			<button type="submit" class="btn btn-primary px-4 fw-bold">
				<i class="ti tabler-device-floppy me-1"></i><?= htmlspecialchars($language::get('firewall_save_settings')); ?>
			</button>
		</div>

	</form>

</div>
