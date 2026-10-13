<?php
use XcVm\Module\Firewall\FirewallTranslator;
$language = FirewallTranslator::class;
?>
<script>
let fwActiveLogType = 'security';
const fwLang = {
	confirmAction: <?= json_encode($language::get('firewall_confirm_action', 'Are you sure you want to perform this service action?')); ?>,
	installing: <?= json_encode($language::get('firewall_installing', 'Installing Fail2ban... please wait')); ?>,
	confirmUnban: <?= json_encode($language::get('firewall_confirm_unban', 'Are you sure you want to unban IP')); ?>,
	settingsSaved: <?= json_encode($language::get('firewall_settings_saved', 'Firewall settings saved and rules reloaded.')); ?>,
	connError: <?= json_encode($language::get('firewall_conn_error', 'Connection or network error')); ?>,
	successTitle: <?= json_encode($language::get('success', 'Success')); ?>,
	errorTitle: <?= json_encode($language::get('error', 'Error')); ?>,
	confirmBtn: <?= json_encode($language::get('confirm', 'Confirm')); ?>,
	cancelBtn: <?= json_encode($language::get('cancel', 'Cancel')); ?>,
	zeroBannedTitle: <?= json_encode($language::get('firewall_no_banned_title', 'Zero Banned IPs')); ?>,
	zeroBannedDesc: <?= json_encode($language::get('firewall_no_banned_desc', 'All protected endpoints are clear and healthy.')); ?>,
	noRulesFound: <?= json_encode($language::get('firewall_no_rules_found', 'No Rules Found')); ?>,
	onboardingDeploying: <?= json_encode($language::get('firewall_onboarding_deploying', 'Configuring and starting defense engine... please wait')); ?>,
	onboardingSuccess: <?= json_encode($language::get('firewall_onboarding_success', 'Fail2ban protection suite configured and active!')); ?>,
	versionUpgrading: <?= json_encode($language::get('firewall_version_upgrading', 'Upgrading Fail2ban via APT...')); ?>
};

/**
 * Dynamically build the exact API URL preserving the active panel access code.
 * E.g. /3yRv7Adq/firewall_settings -> /3yRv7Adq/api?action=...
 */
function fwApiUrl(action) {
	const parts = window.location.pathname.split('/').filter(Boolean);
	const accessCode = parts[0] || '';
	const base = accessCode ? '/' + accessCode + '/api' : 'api';
	return base + '?action=' + encodeURIComponent(action);
}

/**
 * Robust JSON fetcher that cleanly handles empty or non-JSON responses.
 */
async function fwFetchJson(url, options = {}) {
	const res = await fetch(url, options);
	const text = await res.text();
	if (!text.trim()) {
		throw new Error('Empty response from server (HTTP ' + res.status + ')');
	}
	try {
		return JSON.parse(text);
	} catch (e) {
		console.error('Non-JSON response:', text);
		throw new Error('Invalid server response: ' + text.substring(0, 120));
	}
}

/**
 * Display alert modal with SweetAlert2 or native fallback
 */
function fwNotify(title, message, icon = 'success') {
	if (typeof Swal !== 'undefined') {
		return Swal.fire({
			title: title,
			text: message,
			icon: icon,
			customClass: {
				confirmButton: 'btn btn-primary'
			},
			buttonsStyling: false
		});
	}
	alert((title ? title + ': ' : '') + message);
	return Promise.resolve();
}

/**
 * Filter banned table by input (routed through DataTables with fallback)
 */
document.addEventListener('DOMContentLoaded', function() {
	const filterInput = document.getElementById('filterBannedInput');
	if (filterInput) {
		filterInput.addEventListener('keyup', function() {
			if (window.dtBanned) {
				window.dtBanned.search(this.value.trim()).draw();
			} else {
				const term = this.value.toLowerCase().trim();
				const rows = document.querySelectorAll('#bannedTable tbody tr');
				rows.forEach(row => {
					const text = row.textContent.toLowerCase();
					row.style.display = text.includes(term) ? '' : 'none';
				});
			}
		});
	}
});

/**
 * Control Fail2ban system service (start, stop, restart, reload)
 */
function fwServiceAction(action) {
	const promptText = fwLang.confirmAction + ' (' + action.toUpperCase() + ')';
	
	const doAction = () => {
		const formData = new FormData();
		formData.append('service_action', action);

		fwFetchJson(fwApiUrl('firewall_service_control'), {
			method: 'POST',
			body: formData
		})
		.then(data => {
			if (data.status === 'success') {
				fwNotify(fwLang.successTitle, data.message, 'success').then(() => {
					location.reload();
				});
			} else {
				fwNotify(fwLang.errorTitle, data.message || 'Action failed', 'error');
			}
		})
		.catch(err => {
			fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
		});
	};

	if (typeof Swal !== 'undefined') {
		Swal.fire({
			title: action.toUpperCase(),
			text: promptText,
			icon: 'warning',
			showCancelButton: true,
			confirmButtonText: fwLang.confirmBtn,
			cancelButtonText: fwLang.cancelBtn,
			customClass: {
				confirmButton: 'btn btn-primary me-2',
				cancelButton: 'btn btn-label-secondary'
			},
			buttonsStyling: false
		}).then(res => {
			if (res.isConfirmed) doAction();
		});
	} else {
		if (confirm(promptText)) doAction();
	}
}

/**
 * Install Fail2ban package
 */
function fwInstall() {
	const btn = document.getElementById('btnInstallFail2ban');
	if (btn) {
		btn.disabled = true;
		btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' + fwLang.installing;
	}

	fwFetchJson(fwApiUrl('firewall_install'), {
		method: 'POST'
	})
	.then(data => {
		fwNotify(data.status === 'success' ? fwLang.successTitle : fwLang.errorTitle, data.message, data.status === 'success' ? 'success' : 'error').then(() => {
			location.reload();
		});
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, 'Installation error: ' + err.message, 'error');
		if (btn) {
			btn.disabled = false;
			btn.innerHTML = '<i class="ti tabler-download me-1"></i>Install Fail2ban';
		}
	});
}

/**
 * Unban an IP address
 */
function fwUnban(ip, jail) {
	const promptText = fwLang.confirmUnban + ' ' + ip + '?';

	const doUnban = () => {
		const formData = new FormData();
		formData.append('ip', ip);
		formData.append('jail', jail || '');

		fwFetchJson(fwApiUrl('firewall_unban'), {
			method: 'POST',
			body: formData
		})
		.then(data => {
			if (data.status === 'success') {
				fwNotify(fwLang.successTitle, data.message, 'success').then(() => {
					location.reload();
				});
			} else {
				fwNotify(fwLang.errorTitle, data.message, 'error');
			}
		})
		.catch(err => {
			fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
		});
	};

	if (typeof Swal !== 'undefined') {
		Swal.fire({
			title: 'Unban IP',
			text: promptText,
			icon: 'question',
			showCancelButton: true,
			confirmButtonText: fwLang.confirmBtn,
			cancelButtonText: fwLang.cancelBtn,
			customClass: {
				confirmButton: 'btn btn-success me-2',
				cancelButton: 'btn btn-label-secondary'
			},
			buttonsStyling: false
		}).then(res => {
			if (res.isConfirmed) doUnban();
		});
	} else {
		if (confirm(promptText)) doUnban();
	}
}

/**
 * Submit manual ban form
 */
function fwSubmitManualBan(e) {
	e.preventDefault();
	const form = e.target;
	const formData = new FormData(form);

	fwFetchJson(fwApiUrl('firewall_ban'), {
		method: 'POST',
		body: formData
	})
	.then(data => {
		if (data.status === 'success') {
			fwNotify(fwLang.successTitle, data.message, 'success').then(() => {
				location.reload();
			});
		} else {
			fwNotify(fwLang.errorTitle, data.message, 'error');
		}
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
	});
}

/**
 * Apply preset values in settings view
 */
function fwSelectPreset(preset) {
	const r = document.getElementById('preset_' + preset);
	if (r) {
		r.checked = true;
	}
	fwApplyPreset(preset);
}

function fwApplyPreset(preset) {
	document.querySelectorAll('.fw-preset-card').forEach(c => c.classList.remove('active'));
	const activeCard = document.getElementById('cardPreset_' + preset);
	if (activeCard) {
		activeCard.classList.add('active');
	}

	if (preset === 'balanced') {
		// SSH
		if (document.getElementById('sshd_maxretry')) document.getElementById('sshd_maxretry').value = 5;
		if (document.getElementById('sshd_findtime')) document.getElementById('sshd_findtime').value = 600;
		if (document.getElementById('sshd_bantime')) document.getElementById('sshd_bantime').value = 86400;
		// Panel
		if (document.getElementById('panel_maxretry')) document.getElementById('panel_maxretry').value = 5;
		if (document.getElementById('panel_findtime')) document.getElementById('panel_findtime').value = 600;
		if (document.getElementById('panel_bantime')) document.getElementById('panel_bantime').value = 7200;
		// Stream
		if (document.getElementById('stream_maxretry')) document.getElementById('stream_maxretry').value = 10;
		if (document.getElementById('stream_findtime')) document.getElementById('stream_findtime').value = 300;
		if (document.getElementById('stream_bantime')) document.getElementById('stream_bantime').value = 3600;
		// Flood
		if (document.getElementById('flood_maxretry')) document.getElementById('flood_maxretry').value = 120;
		if (document.getElementById('flood_findtime')) document.getElementById('flood_findtime').value = 60;
		if (document.getElementById('flood_bantime')) document.getElementById('flood_bantime').value = 1800;
	} else if (preset === 'strict') {
		// SSH
		if (document.getElementById('sshd_maxretry')) document.getElementById('sshd_maxretry').value = 3;
		if (document.getElementById('sshd_findtime')) document.getElementById('sshd_findtime').value = 600;
		if (document.getElementById('sshd_bantime')) document.getElementById('sshd_bantime').value = 259200;
		// Panel
		if (document.getElementById('panel_maxretry')) document.getElementById('panel_maxretry').value = 3;
		if (document.getElementById('panel_findtime')) document.getElementById('panel_findtime').value = 600;
		if (document.getElementById('panel_bantime')) document.getElementById('panel_bantime').value = 86400;
		// Stream
		if (document.getElementById('stream_maxretry')) document.getElementById('stream_maxretry').value = 5;
		if (document.getElementById('stream_findtime')) document.getElementById('stream_findtime').value = 600;
		if (document.getElementById('stream_bantime')) document.getElementById('stream_bantime').value = 86400;
		// Flood
		if (document.getElementById('flood_maxretry')) document.getElementById('flood_maxretry').value = 60;
		if (document.getElementById('flood_findtime')) document.getElementById('flood_findtime').value = 60;
		if (document.getElementById('flood_bantime')) document.getElementById('flood_bantime').value = 7200;
	} else if (preset === 'aggressive') {
		// SSH
		if (document.getElementById('sshd_maxretry')) document.getElementById('sshd_maxretry').value = 2;
		if (document.getElementById('sshd_findtime')) document.getElementById('sshd_findtime').value = 300;
		if (document.getElementById('sshd_bantime')) document.getElementById('sshd_bantime').value = 604800;
		// Panel
		if (document.getElementById('panel_maxretry')) document.getElementById('panel_maxretry').value = 2;
		if (document.getElementById('panel_findtime')) document.getElementById('panel_findtime').value = 300;
		if (document.getElementById('panel_bantime')) document.getElementById('panel_bantime').value = 172800;
		// Stream
		if (document.getElementById('stream_maxretry')) document.getElementById('stream_maxretry').value = 3;
		if (document.getElementById('stream_findtime')) document.getElementById('stream_findtime').value = 300;
		if (document.getElementById('stream_bantime')) document.getElementById('stream_bantime').value = 259200;
		// Flood
		if (document.getElementById('flood_maxretry')) document.getElementById('flood_maxretry').value = 30;
		if (document.getElementById('flood_findtime')) document.getElementById('flood_findtime').value = 60;
		if (document.getElementById('flood_bantime')) document.getElementById('flood_bantime').value = 86400;
	}
}


/**
 * Save settings form via AJAX
 */
function fwSaveSettingsForm(e) {
	if (e) e.preventDefault();
	const form = document.getElementById('formFirewallSettings');
	if (!form) return;

	const formData = new FormData(form);

	fwFetchJson(fwApiUrl('firewall_save_settings'), {
		method: 'POST',
		body: formData
	})
	.then(data => {
		if (data.status === 'success') {
			fwNotify(fwLang.successTitle, fwLang.settingsSaved, 'success').then(() => {
				location.reload();
			});
		} else {
			fwNotify(fwLang.errorTitle, data.message || 'Failed to save settings', 'error');
		}
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
	});
}

/**
 * Refresh current active log view
 */
function fwRefreshCurrentLogs() {
	fwFetchJson(fwApiUrl('firewall_get_logs') + '&type=' + encodeURIComponent(fwActiveLogType) + '&lines=120')
	.then(data => {
		if (data.status === 'success' && data.data) {
			const targetId = fwActiveLogType === 'security' ? 'preSecurityLogs' : 'preFail2banLogs';
			const el = document.getElementById(targetId);
			if (el) {
				el.textContent = data.data.lines.join('\n');
				el.scrollTop = el.scrollHeight;
			}
		}
	})
	.catch(err => {
		console.error('Failed to refresh logs:', err);
	});
}

/**
 * Re-deploy filter rules and reload Fail2ban
 */
function fwDeploy() {
	const doDeploy = () => {
		fwFetchJson(fwApiUrl('firewall_deploy'), { method: 'POST' })
		.then(data => {
			fwNotify(data.status === 'success' ? fwLang.successTitle : fwLang.errorTitle, data.message, data.status === 'success' ? 'success' : 'error').then(() => {
				location.reload();
			});
		})
		.catch(err => {
			fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
		});
	};

	if (typeof Swal !== 'undefined') {
		Swal.fire({
			title: 'Re-deploy Rules',
			text: 'Re-deploy Fail2ban filters and reload jail rules?',
			icon: 'info',
			showCancelButton: true,
			confirmButtonText: fwLang.confirmBtn,
			cancelButtonText: fwLang.cancelBtn,
			customClass: {
				confirmButton: 'btn btn-primary me-2',
				cancelButton: 'btn btn-label-secondary'
			},
			buttonsStyling: false
		}).then(res => {
			if (res.isConfirmed) doDeploy();
		});
	} else {
		if (confirm('Re-deploy Fail2ban filters and reload rules?')) doDeploy();
	}
}

/**
 * Synchronize Fail2ban active bans with database and cluster
 */
function fwSync() {
	fwFetchJson(fwApiUrl('firewall_sync'), { method: 'POST' })
	.then(data => {
		fwNotify(data.status === 'success' ? fwLang.successTitle : fwLang.errorTitle, data.message, data.status === 'success' ? 'success' : 'error').then(() => {
			location.reload();
		});
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, fwLang.connError + ' (' + err.message + ')', 'error');
	});
}

/**
 * Universal Clipboard copy helper (works in HTTPS and HTTP/insecure IP contexts)
 */
function fwCopyToClipboard(text) {
	if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function' && window.isSecureContext) {
		return navigator.clipboard.writeText(text).catch(() => {
			return fwFallbackCopy(text);
		});
	}
	return fwFallbackCopy(text);
}

function fwFallbackCopy(text) {
	return new Promise((resolve, reject) => {
		try {
			const temp = document.createElement('textarea');
			temp.value = text;
			temp.setAttribute('readonly', '');
			temp.style.position = 'fixed';
			temp.style.left = '-9999px';
			temp.style.top = '-9999px';
			document.body.appendChild(temp);
			temp.focus();
			temp.select();
			const success = document.execCommand('copy');
			document.body.removeChild(temp);
			if (success) {
				resolve();
			} else {
				reject(new Error('Copy command failed'));
			}
		} catch (e) {
			reject(e);
		}
	});
}

/**
 * Copy CLI command to clipboard with UI feedback
 */
function fwCopyCmd(text, btn) {
	fwCopyToClipboard(text).then(() => {
		if (btn) {
			const orig = btn.innerHTML;
			btn.innerHTML = '<i class="ti tabler-check me-1"></i><?= addslashes($language::get('firewall_copied', 'Copied!')); ?>';
			btn.classList.add('btn-success');
			btn.classList.remove('btn-outline-secondary');
			setTimeout(() => {
				btn.innerHTML = orig;
				btn.classList.remove('btn-success');
				btn.classList.add('btn-outline-secondary');
			}, 1800);
		}
	}).catch(err => {
		console.warn('Clipboard copy error:', err);
		if (window.fwNotify) {
			fwNotify(fwLang.errorTitle, '<?= addslashes($language::get('firewall_click_to_copy', 'Click to copy')); ?>: ' + text, 'info');
		} else {
			alert(text);
		}
	});
}

/**
 * Live Telemetry Monitor Auto-Refresh & SOC Beacon
 */
let fwMonitorInterval = null;

function fwClickSocPill(e) {
	if (e && e.target && e.target.id === 'switchAutoRefresh') return;
	const sw = document.getElementById('switchAutoRefresh');
	if (sw) {
		sw.checked = !sw.checked;
		fwToggleAutoRefresh(sw);
	}
}

function fwToggleAutoRefresh(toggle) {
	const isChecked = Boolean(toggle && toggle.checked);
	const pill = document.getElementById('fwSocTogglePill');
	const badge = document.getElementById('fwLiveStatusBadge');

	if (pill) {
		pill.classList.toggle('active', isChecked);
	}

	if (badge) {
		const text = isChecked
			? (badge.getAttribute('data-text-active') || '10s &bull; Active')
			: (badge.getAttribute('data-text-paused') || '10s &bull; Paused');
		badge.innerHTML = text;
	}

	if (isChecked) {
		try { localStorage.setItem('xcvm_fw_auto_refresh', '1'); } catch (e) {}
		fwRefreshLiveMonitor();
		if (!fwMonitorInterval) {
			fwMonitorInterval = setInterval(fwRefreshLiveMonitor, 10000);
		}
	} else {
		try { localStorage.setItem('xcvm_fw_auto_refresh', '0'); } catch (e) {}
		if (fwMonitorInterval) {
			clearInterval(fwMonitorInterval);
			fwMonitorInterval = null;
		}
	}
}

function fwRefreshLiveMonitor() {
	fwFetchJson(fwApiUrl('firewall_get_monitor'))
	.then(res => {
		if (res.status === 'success' && res.data) {
			const d = res.data;
			const elBanned = document.getElementById('statTotalBanned');
			if (elBanned && d.status) elBanned.textContent = d.status.total_banned ?? 0;

			const elFailed = document.getElementById('statTotalFailed');
			if (elFailed) elFailed.textContent = d.total_currently_failed ?? 0;

			const elDbBlocked = document.getElementById('statDbBlocked');
			if (elDbBlocked) elDbBlocked.textContent = d.db_blocked_count ?? 0;

			const elUptime = document.getElementById('badgeUptime');
			if (elUptime && d.uptime) elUptime.textContent = d.uptime;

			const elPid = document.getElementById('badgePid');
			if (elPid && d.pid) elPid.textContent = 'PID: ' + d.pid;

			if (d.fail2ban_feed && document.getElementById('preFail2banFeed')) {
				document.getElementById('preFail2banFeed').textContent = d.fail2ban_feed.join('\n');
			}
			if (d.security_feed && document.getElementById('preSecurityFeed')) {
				document.getElementById('preSecurityFeed').textContent = d.security_feed.join('\n');
			}

			const indicator = document.getElementById('liveRefreshPulse');
			if (indicator) {
				indicator.classList.add('flash-heartbeat');
				setTimeout(() => indicator.classList.remove('flash-heartbeat'), 700);
			}
		}
	})
	.catch(err => {
		console.warn('Auto-refresh poll error:', err);
	});
}

/**
 * DataTables Responsive & Buttons Initialization
 * Covers: #rulesTable, #bannedTable, #historyTable, #cliTable
 */
$(function() {
	if (window.jQuery && $.fn.dataTable) {
		$.fn.dataTable.ext.errMode = 'none';
	}

	const dtExportButtons = [
		{ extend: 'copy', className: 'btn btn-sm btn-label-secondary me-1', text: '<i class="ti tabler-copy me-1"></i>Copy' },
		{ extend: 'csv', className: 'btn btn-sm btn-label-primary me-1', text: '<i class="ti tabler-file-spreadsheet me-1"></i>CSV' },
		{ extend: 'excel', className: 'btn btn-sm btn-label-success me-1', text: '<i class="ti tabler-file-analytics me-1"></i>Excel' },
		{ extend: 'pdf', className: 'btn btn-sm btn-label-danger me-1', text: '<i class="ti tabler-file-text me-1"></i>PDF' },
		{ extend: 'print', className: 'btn btn-sm btn-label-info', text: '<i class="ti tabler-printer me-1"></i>Print' }
	];

	// 1. Security Rules Table
	if (window.jQuery && $.fn.DataTable && $('#rulesTable').length) {
		window.dtRules = $('#rulesTable').DataTable({
			responsive: true,
			order: [[0, 'asc']],
			columnDefs: [
				{ targets: 'no-sort', orderable: false, searchable: false }
			],
			pageLength: 25,
			language: {
				emptyTable: '<div class="d-flex flex-column align-items-center justify-content-center text-center py-4"><i class="ti tabler-shield-off fs-1 text-secondary mb-2"></i><h6 class="fw-bold mb-1">' + (fwLang.noRulesFound || 'No Rules Found') + '</h6><p class="small text-muted mb-0">No firewall rules match the selected criteria.</p></div>'
			},
			dom: '<"card-header d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"d-flex align-items-center gap-2"lB><"d-flex align-items-center"f>>rt<"card-footer d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"small text-muted"i><"pagination-sm"p>>',
			layout: {
				topStart: {
					pageLength: {},
					buttons: dtExportButtons
				},
				topEnd: 'search'
			},
			buttons: dtExportButtons
		});

		const filterRulesInput = document.getElementById('filterRulesInput');
		if (filterRulesInput) {
			filterRulesInput.addEventListener('keyup', function() {
				if (window.dtRules) {
					window.dtRules.search(this.value.trim()).draw();
				}
			});
		}
	}

	// 2. Banned IP Table
	if (window.jQuery && $.fn.DataTable && $('#bannedTable').length) {
		window.dtBanned = $('#bannedTable').DataTable({
			responsive: true,
			order: [[0, 'asc']],
			columnDefs: [
				{ targets: 'no-sort', orderable: false, searchable: false }
			],
			pageLength: 10,
			language: {
				emptyTable: '<div class="d-flex flex-column align-items-center justify-content-center text-center py-5"><i class="ti tabler-shield-check fs-1 text-success mb-2"></i><h6 class="fw-bold mb-1">' + (fwLang.zeroBannedTitle || 'Zero Banned IPs') + '</h6><p class="small text-muted mb-0">' + (fwLang.zeroBannedDesc || 'All protected endpoints are clear and healthy.') + '</p></div>'
			},
			dom: '<"card-header d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"d-flex align-items-center gap-2"lB><"d-flex align-items-center"f>>rt<"card-footer d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"small text-muted"i><"pagination-sm"p>>',
			layout: {
				topStart: {
					pageLength: {},
					buttons: dtExportButtons
				},
				topEnd: 'search'
			},
			buttons: dtExportButtons
		});

		const filterBannedInput = document.getElementById('filterBannedInput');
		if (filterBannedInput) {
			filterBannedInput.addEventListener('keyup', function() {
				if (window.dtBanned) {
					window.dtBanned.search(this.value.trim()).draw();
				}
			});
		}
	}

	// 3. Security Action Audit History Table
	if (window.jQuery && $.fn.DataTable && $('#historyTable').length) {
		window.dtHistory = $('#historyTable').DataTable({
			responsive: true,
			order: [[0, 'desc']],
			pageLength: 10,
			dom: '<"card-header d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"d-flex align-items-center gap-2"lB><"d-flex align-items-center"f>>rt<"card-footer d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"small text-muted"i><"pagination-sm"p>>',
			layout: {
				topStart: {
					pageLength: {},
					buttons: dtExportButtons
				},
				topEnd: 'search'
			},
			buttons: dtExportButtons
		});
	}

	// 4. Terminal & CLI Command Reference Table
	if (window.jQuery && $.fn.DataTable && $('#cliTable').length) {
		window.dtCli = $('#cliTable').DataTable({
			responsive: true,
			order: [[0, 'asc']],
			columnDefs: [
				{ targets: 'no-sort', orderable: false, searchable: false }
			],
			pageLength: 10,
			dom: '<"card-header d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"d-flex align-items-center gap-2"lB><"d-flex align-items-center"f>>rt<"card-footer d-flex flex-wrap justify-content-between align-items-center p-3 gap-2"<"small text-muted"i><"pagination-sm"p>>',
			layout: {
				topStart: {
					pageLength: {},
					buttons: [
						{ extend: 'copy', className: 'btn btn-sm btn-label-secondary me-1', text: '<i class="ti tabler-copy me-1"></i>Copy' },
						{ extend: 'print', className: 'btn btn-sm btn-label-info', text: '<i class="ti tabler-printer me-1"></i>Print' }
					]
				},
				topEnd: 'search'
			},
			buttons: [
				{ extend: 'copy', className: 'btn btn-sm btn-label-secondary me-1', text: '<i class="ti tabler-copy me-1"></i>Copy' },
				{ extend: 'print', className: 'btn btn-sm btn-label-info', text: '<i class="ti tabler-printer me-1"></i>Print' }
			]
		});
	}

	// Restore remembered Live SOC Auto-Refresh state
	try {
		const savedAutoRefresh = localStorage.getItem('xcvm_fw_auto_refresh');
		const sw = document.getElementById('switchAutoRefresh');
		if (savedAutoRefresh === '1' && sw && !sw.checked) {
			sw.checked = true;
			fwToggleAutoRefresh(sw);
		}
	} catch (e) {}
});

/**
 * Filter rules table by category tab (all, default, custom)
 */
function fwFilterRules(cat) {
	const btns = document.querySelectorAll('#ruleCategoryFilter button');
	btns.forEach(b => b.classList.remove('active'));
	if (window.event && window.event.target) {
		window.event.target.classList.add('active');
	}

	if (window.dtRules) {
		if (cat === 'all') {
			window.dtRules.column(1).search('').draw();
		} else if (cat === 'default') {
			window.dtRules.column(1).search('Core|افتراضي', true, false).draw();
		} else if (cat === 'custom') {
			window.dtRules.column(1).search('Custom|مخصص', true, false).draw();
		}
	} else {
		const rows = document.querySelectorAll('#rulesTable tbody tr.rule-row');
		rows.forEach(row => {
			const rowCat = row.getAttribute('data-category');
			if (cat === 'all' || rowCat === cat) {
				row.style.display = '';
			} else {
				row.style.display = 'none';
			}
		});
	}
}

/**
 * Open Modal to add a new custom rule
 */
function fwOpenAddRuleModal() {
	document.getElementById('formRuleEditor').reset();
	document.getElementById('ruleInputKey').removeAttribute('readonly');
	document.getElementById('ruleInputCategory').value = 'custom';
	document.getElementById('modalRuleTitle').innerHTML = '<i class="ti tabler-plus me-2 text-primary"></i>' + (fwLang.createRuleTitle || 'Create New Security Rule');
	const modal = new bootstrap.Modal(document.getElementById('modalRuleEditor'));
	modal.show();
}

/**
 * Open Modal to edit an existing rule
 */
function fwOpenEditRuleModal(rule) {
	document.getElementById('ruleInputKey').value = rule.rule_key || '';
	document.getElementById('ruleInputKey').setAttribute('readonly', 'readonly');
	document.getElementById('ruleInputName').value = rule.name || '';
	document.getElementById('ruleInputCategory').value = rule.category || 'custom';
	document.getElementById('ruleInputPort').value = rule.port || '80,443';
	document.getElementById('ruleInputProtocol').value = rule.protocol || 'tcp';
	document.getElementById('ruleInputActionType').value = rule.action_type || 'iptables-multiport';
	document.getElementById('ruleInputMaxretry').value = rule.maxretry || 5;
	document.getElementById('ruleInputFindtime').value = rule.findtime || 600;
	document.getElementById('ruleInputBantime').value = rule.bantime || 3600;
	document.getElementById('ruleInputLogPath').value = rule.log_path || '/var/log/xcvm/security.log';
	document.getElementById('ruleInputFilterRegex').value = rule.filter_regex || '';
	document.getElementById('ruleInputDescription').value = rule.description || '';
	document.getElementById('ruleInputEnabled').checked = (parseInt(rule.enabled) === 1);

	document.getElementById('modalRuleTitle').innerHTML = '<i class="ti tabler-edit me-2 text-primary"></i>' + (fwLang.editRuleTitle || 'Edit Rule: ') + rule.rule_key;
	const modal = new bootstrap.Modal(document.getElementById('modalRuleEditor'));
	modal.show();
}

/**
 * Submit Rule Editor form (Save / Update rule)
 */
function fwSubmitRuleForm(e) {
	e.preventDefault();
	const form = document.getElementById('formRuleEditor');
	const fd = new FormData(form);

	const btn = document.getElementById('btnSaveRuleSubmit');
	const orig = btn.innerHTML;
	btn.disabled = true;
	btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Saving...';

	fwFetchJson(fwApiUrl('firewall_save_rule'), {
		method: 'POST',
		body: fd
	})
	.then(res => {
		btn.disabled = false;
		btn.innerHTML = orig;
		if (res.status === 'success') {
			bootstrap.Modal.getInstance(document.getElementById('modalRuleEditor')).hide();
			fwNotify(fwLang.successTitle, res.message, 'success').then(() => {
				location.reload();
			});
		} else {
			fwNotify(fwLang.errorTitle, res.message || 'Failed to save rule', 'error');
		}
	})
	.catch(err => {
		btn.disabled = false;
		btn.innerHTML = orig;
		fwNotify(fwLang.errorTitle, err.message, 'error');
	});
}

/**
 * Toggle active status of a rule
 */
function fwToggleRule(ruleKey, cb) {
	const fd = new FormData();
	fd.append('rule_key', ruleKey);
	fd.append('enabled', cb.checked ? 1 : 0);

	fwFetchJson(fwApiUrl('firewall_toggle_rule'), {
		method: 'POST',
		body: fd
	})
	.then(res => {
		if (res.status !== 'success') {
			cb.checked = !cb.checked;
			fwNotify(fwLang.errorTitle, res.message || 'Failed to toggle rule', 'error');
		}
	})
	.catch(err => {
		cb.checked = !cb.checked;
		fwNotify(fwLang.errorTitle, err.message, 'error');
	});
}

/**
 * Delete a custom rule
 */
function fwDeleteRule(ruleKey) {
	if (typeof Swal !== 'undefined') {
		Swal.fire({
			title: 'Delete Rule',
			text: 'Are you sure you want to delete custom rule "' + ruleKey + '"?',
			icon: 'warning',
			showCancelButton: true,
			confirmButtonText: 'Yes, Delete',
			cancelButtonText: 'Cancel',
			customClass: {
				confirmButton: 'btn btn-danger me-2',
				cancelButton: 'btn btn-secondary'
			},
			buttonsStyling: false
		}).then(result => {
			if (result.isConfirmed) {
				doDeleteRule(ruleKey);
			}
		});
	} else if (confirm('Are you sure you want to delete rule ' + ruleKey + '?')) {
		doDeleteRule(ruleKey);
	}
}

function doDeleteRule(ruleKey) {
	const fd = new FormData();
	fd.append('rule_key', ruleKey);

	fwFetchJson(fwApiUrl('firewall_delete_rule'), {
		method: 'POST',
		body: fd
	})
	.then(res => {
		if (res.status === 'success') {
			fwNotify(fwLang.successTitle, res.message, 'success').then(() => {
				location.reload();
			});
		} else {
			fwNotify(fwLang.errorTitle, res.message || 'Failed to delete rule', 'error');
		}
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, err.message, 'error');
	});
}

/**
 * Reset default core rules to factory defaults
 */
function fwResetDefaultRules() {
	if (typeof Swal !== 'undefined') {
		Swal.fire({
			title: 'Reset Default Rules',
			text: 'Reset all core project rules to their factory default settings?',
			icon: 'warning',
			showCancelButton: true,
			confirmButtonText: 'Reset Defaults',
			cancelButtonText: 'Cancel',
			customClass: {
				confirmButton: 'btn btn-warning me-2',
				cancelButton: 'btn btn-secondary'
			},
			buttonsStyling: false
		}).then(result => {
			if (result.isConfirmed) {
				doResetDefaultRules();
			}
		});
	} else if (confirm('Reset all core project rules to factory defaults?')) {
		doResetDefaultRules();
	}
}

function doResetDefaultRules() {
	fwFetchJson(fwApiUrl('firewall_reset_default_rules'), {
		method: 'POST'
	})
	.then(res => {
		if (res.status === 'success') {
			fwNotify(fwLang.successTitle, res.message, 'success').then(() => {
				location.reload();
			});
		} else {
			fwNotify(fwLang.errorTitle, res.message || 'Failed to reset rules', 'error');
		}
	})
	.catch(err => {
		fwNotify(fwLang.errorTitle, err.message, 'error');
	});
}

/**
 * Open Regex Tester Modal
 */
function fwOpenTestRegexModal(regex) {
	document.getElementById('regexTesterInput').value = regex || '';
	document.getElementById('regexTesterOutput').innerHTML = '<span class="text-muted">Click test to validate pattern.</span>';
	const modal = new bootstrap.Modal(document.getElementById('modalRegexTester'));
	modal.show();
}

function fwOpenTestRegexWithCurrent() {
	const current = document.getElementById('ruleInputFilterRegex').value;
	fwOpenTestRegexModal(current);
}

/**
 * Execute regex validation test against sample log
 */
function fwExecuteRegexTest() {
	const regex = document.getElementById('regexTesterInput').value;
	const sample = document.getElementById('regexTesterSample').value;
	const out = document.getElementById('regexTesterOutput');

	out.innerHTML = '<span class="text-info"><i class="spinner-border spinner-border-sm me-1"></i>Testing pattern...</span>';

	const fd = new FormData();
	fd.append('regex', regex);
	fd.append('sample_log', sample);

	fwFetchJson(fwApiUrl('firewall_test_regex'), {
		method: 'POST',
		body: fd
	})
	.then(res => {
		if (res.status === 'success') {
			if (res.matches > 0) {
				out.innerHTML = '<div class="text-success fw-bold"><i class="ti tabler-circle-check me-1"></i>' + res.message + '</div>';
			} else {
				out.innerHTML = '<div class="text-warning fw-bold"><i class="ti tabler-alert-triangle me-1"></i>' + res.message + '</div>';
			}
		} else {
			out.innerHTML = '<div class="text-danger fw-bold"><i class="ti tabler-circle-x me-1"></i>' + res.message + '</div>';
		}
	})
	.catch(err => {
		out.innerHTML = '<div class="text-danger fw-bold"><i class="ti tabler-circle-x me-1"></i>' + err.message + '</div>';
	});
}

/**
 * First-Time Setup Wizard Modal
 */
function fwOpenOnboardingModal() {
	const modalEl = document.getElementById('modalFirstTimeSetup');
	if (modalEl) {
		const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
		modal.show();
	}
}

/**
 * Handle Onboarding Form Submission
 */
async function fwSubmitOnboarding(e) {
	if (e) e.preventDefault();
	const form = document.getElementById('formOnboardingModal');
	const btn = document.getElementById('btnSubmitOnboard');
	const statusBox = document.getElementById('onboardingStatusBox');
	const statusText = document.getElementById('onboardingStatusText');

	if (!form) return;

	const fd = new FormData(form);
	btn.disabled = true;
	btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + (fwLang.installing || 'Deploying...');
	statusBox.classList.remove('d-none');
	statusText.textContent = fwLang.onboardingDeploying || 'Configuring and starting defense engine... please wait';

	try {
		const res = await fwFetchJson(fwApiUrl('firewall_complete_onboarding'), {
			method: 'POST',
			body: fd
		});

		if (res.status === 'success') {
			statusBox.className = 'alert alert-success mt-3 mb-0';
			statusText.innerHTML = '<i class="ti tabler-circle-check me-2"></i>' + (res.message || fwLang.onboardingSuccess);
			await fwNotify(fwLang.successTitle, res.message || fwLang.onboardingSuccess, 'success');
			location.reload();
		} else {
			statusBox.className = 'alert alert-danger mt-3 mb-0';
			statusText.innerHTML = '<i class="ti tabler-alert-triangle me-2"></i>' + (res.message || 'Onboarding failed');
			btn.disabled = false;
			btn.innerHTML = '<i class="ti tabler-shield-check me-1"></i>Deploy Protection Suite';
		}
	} catch (err) {
		statusBox.className = 'alert alert-danger mt-3 mb-0';
		statusText.innerHTML = '<i class="ti tabler-alert-triangle me-2"></i>' + (err.message || fwLang.connError);
		btn.disabled = false;
		btn.innerHTML = '<i class="ti tabler-shield-check me-1"></i>Deploy Protection Suite';
	}
}

/**
 * Open Version Inspector Modal
 */
function fwOpenVersionModal() {
	const modalEl = document.getElementById('modalVersionInfo');
	if (modalEl) {
		const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
		modal.show();
	}
}

/**
 * Check for Fail2ban Updates (queries local & GitHub)
 */
async function fwCheckVersionUpdate(force = false) {
	try {
		const url = fwApiUrl('firewall_check_versions') + (force ? '&force=1' : '');
		const res = await fwFetchJson(url);
		if (res.status === 'success' && res.data) {
			const d = res.data;
			window.fwVersionInfo = d;
			// Update modal fields
			const installedEl = document.getElementById('verModalInstalled');
			const upstreamEl = document.getElementById('verModalUpstream');
			const badgeEl = document.getElementById('verModalStatusBadge');
			const aptEl = document.getElementById('verModalApt');
			const tagEl = document.getElementById('verModalTag');
			const alertBox = document.getElementById('verModalAlertBox');

			if (installedEl) installedEl.textContent = d.installed_version || 'None';
			if (upstreamEl) upstreamEl.textContent = d.latest_version || 'v1.1.1';
			if (aptEl) aptEl.textContent = d.apt_candidate || 'N/A';
			if (tagEl) tagEl.textContent = d.latest_tag || 'v1.1.1';

			if (badgeEl) {
				badgeEl.className = 'badge ' + (d.is_outdated ? 'bg-label-warning' : 'bg-label-success');
				badgeEl.textContent = d.status_label || (d.is_outdated ? 'Update Available' : 'Up to Date');
			}

			if (alertBox) {
				if (d.is_outdated) {
					alertBox.innerHTML = '<div class="alert alert-warning py-2 mb-0 d-flex align-items-center"><i class="ti tabler-alert-circle me-2 fs-5"></i><div class="small">An official release update (' + (d.latest_version || 'v1.1.1') + ') is available upstream.</div></div>';
				} else {
					alertBox.innerHTML = '<div class="alert alert-success py-2 mb-0 d-flex align-items-center"><i class="ti tabler-circle-check me-2 fs-5"></i><div class="small">The local Fail2ban package is up to date.</div></div>';
				}
			}

			if (force) {
				fwNotify(fwLang.successTitle, 'Version check completed: ' + (d.status_label || 'OK'), 'success');
			}
		}
	} catch (err) {
		if (force) {
			fwNotify(fwLang.errorTitle, err.message || fwLang.connError, 'error');
		}
	}
}

/**
 * Trigger Unattended APT Package Upgrade
 */
async function fwUpgradeFail2ban() {
	if (typeof Swal !== 'undefined') {
		const result = await Swal.fire({
			title: 'Upgrade Fail2ban Package?',
			text: 'This will run apt-get install --only-upgrade fail2ban and reload the daemon.',
			icon: 'warning',
			showCancelButton: true,
			confirmButtonText: 'Yes, upgrade now',
			cancelButtonText: fwLang.cancelBtn,
			customClass: {
				confirmButton: 'btn btn-primary me-2',
				cancelButton: 'btn btn-outline-secondary'
			},
			buttonsStyling: false
		});
		if (!result.isConfirmed) return;
	} else if (!confirm('Upgrade Fail2ban package now?')) {
		return;
	}

	try {
		fwNotify('Upgrading...', fwLang.versionUpgrading || 'Upgrading Fail2ban via APT...', 'info');
		const res = await fwFetchJson(fwApiUrl('firewall_upgrade_fail2ban'), {
			method: 'POST'
		});
		if (res.status === 'success') {
			await fwNotify(fwLang.successTitle, res.message, 'success');
			location.reload();
		} else {
			fwNotify(fwLang.errorTitle, res.message || 'Upgrade failed', 'error');
		}
	} catch (err) {
		fwNotify(fwLang.errorTitle, err.message || fwLang.connError, 'error');
	}
}

// Auto-trigger Onboarding Modal on load if setup is needed
document.addEventListener('DOMContentLoaded', function() {
	if (window.fwOnboardingNeeded) {
		setTimeout(function() {
			fwOpenOnboardingModal();
		}, 600);
	}
});
</script>

</body>
</html>

