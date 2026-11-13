/* ==== Mail Test tab: SMTP / POP3 / IMAP ==== */
(function () {
    'use strict';

    const PROTOCOLS = ['smtp', 'pop', 'imap'];
    const DEFAULT_TO = 'email.kietvu@gmail.com';
    const DEFAULT_PORTS = {
        smtp: { ssl: 465, starttls: 587, none: 25 },
        pop: { ssl: 995, starttls: 110, none: 110 },
        imap: { ssl: 993, starttls: 143, none: 143 }
    };
    const SECURITY_LABELS = {
        ssl: 'SSL/TLS',
        starttls: 'STARTTLS',
        none: 'Không mã hóa'
    };
    const STAGE_LABELS = {
        start: 'Bắt đầu',
        connect: 'Kết nối',
        greeting: 'Greeting',
        tls: 'TLS',
        auth: 'Đăng nhập',
        send: 'Gửi mail',
        mailbox: 'Hộp thư',
        done: 'Hoàn tất',
        error: 'Lỗi'
    };
    const LOG_STATUS_LABELS = {
        ok: 'OK',
        fail: 'Lỗi',
        warn: 'Cảnh báo',
        info: 'Thông tin'
    };

    let controller = null;

    function byId(id) {
        return document.getElementById(id);
    }

    function cap(value) {
        return value.charAt(0).toUpperCase() + value.slice(1);
    }

    function escapeHtml(value) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return String(value == null ? '' : value).replace(/[&<>"']/g, char => map[char]);
    }

    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes < 0) return '-';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function setMessage(type, text) {
        const box = byId('mailTestMessage');
        if (!box) return;
        if (!text) {
            box.innerHTML = '';
            return;
        }
        box.innerHTML = '<div class="message-' + escapeHtml(type) + '">' + escapeHtml(text) + '</div>';
    }

    function emptyState(text) {
        return '<div class="mailtest-empty-state"><p>' + escapeHtml(text) + '</p></div>';
    }

    function setLoading(busy) {
        const button = byId('mailTestBtn');
        if (button) button.disabled = !!busy;

        const results = byId('mailTestResults');
        if (!results) return;
        if (busy) {
            results.innerHTML =
                '<div class="mailtest-loading">' +
                '<div class="spinner"></div>' +
                '<p>Đang kết nối và kiểm tra đăng nhập...</p>' +
                '</div>';
            return;
        }
        if (results.querySelector('.mailtest-loading')) {
            results.innerHTML = emptyState('Chưa có kết quả. Nhập thông tin và bấm Test kết nối.');
        }
    }

    function syncProtocolCard(protocol) {
        const checkbox = byId('mailTest' + cap(protocol) + 'Enabled');
        if (!checkbox) return;
        const card = checkbox.closest('.mailtest-protocol');
        if (card) card.classList.toggle('is-enabled', checkbox.checked);
    }

    function syncFrom() {
        const username = byId('mailTestUsername');
        const from = byId('mailTestSmtpFrom');
        const value = username ? username.value.trim() : '';
        if (username && from) from.value = value;

        const to = byId('mailTestSmtpTo');
        const toggle = byId('mailTestUseUsernameBtn');
        if (to && toggle && toggle.dataset.mode === 'username') {
            to.value = value;
        }
        syncToButton();
    }

    function syncToButton() {
        const button = byId('mailTestUseUsernameBtn');
        const to = byId('mailTestSmtpTo');
        const username = byId('mailTestUsername');
        if (!button || !to) return;
        const toValue = to.value.trim();
        const usernameValue = username ? username.value.trim() : '';
        const usesUsername = !!usernameValue && toValue === usernameValue;
        button.dataset.mode = usesUsername ? 'username' : 'default';
        button.textContent = usesUsername ? 'Dùng Gmail mặc định' : 'Dùng username';
        button.setAttribute('aria-pressed', usesUsername ? 'true' : 'false');
    }

    function syncSmtpSend() {
        const send = byId('mailTestSmtpSend');
        const to = byId('mailTestSmtpTo');
        const useUsername = byId('mailTestUseUsernameBtn');
        const disabled = !!(send && !send.checked);
        if (to) {
            to.disabled = disabled;
            to.classList.toggle('is-disabled', disabled);
        }
        if (useUsername) useUsername.disabled = disabled;
    }

    function collectProtocols() {
        const protocols = {};
        for (const protocol of PROTOCOLS) {
            const enabledEl = byId('mailTest' + cap(protocol) + 'Enabled');
            const portEl = byId('mailTest' + cap(protocol) + 'Port');
            const securityEl = byId('mailTest' + cap(protocol) + 'Security');
            const enabled = !!(enabledEl && enabledEl.checked);

            let port = null;
            if (enabled) {
                port = portEl ? Number(portEl.value) : NaN;
                if (!Number.isInteger(port) || port < 1 || port > 65535) {
                    setMessage('error', 'Port của ' + protocol.toUpperCase() + ' phải là số từ 1 đến 65535.');
                    if (portEl) portEl.focus();
                    return null;
                }
            }

            protocols[protocol] = {
                enabled,
                port: enabled ? port : null,
                security: securityEl ? securityEl.value : 'ssl'
            };
        }
        return protocols;
    }

    function detailRows(result) {
        const details = result.details || {};
        const rows = [];
        if (details.tls) rows.push(['TLS', details.tls]);
        if (details.auth) rows.push(['Đăng nhập', details.auth === 'OK' ? 'Thành công' : details.auth]);
        if (details.from) rows.push(['From', details.from]);
        if (details.messages !== undefined && details.messages !== null) rows.push(['Số thư', String(details.messages)]);
        if (details.size_bytes !== undefined && details.size_bytes !== null) rows.push(['Dung lượng', formatBytes(Number(details.size_bytes))]);
        if (details.sent_to) rows.push(['Đã gửi tới', details.sent_to]);
        if (details.message_id) rows.push(['Message-ID', details.message_id]);
        if (details.mailbox_error) rows.push(['INBOX', details.mailbox_error]);
        if (details.banner) rows.push(['Server', details.banner]);
        return rows;
    }

    function getResultLogs(result) {
        if (Array.isArray(result.logs)) return result.logs;
        const details = result.details || {};
        return Array.isArray(details.logs) ? details.logs : [];
    }

    function renderLogSteps(result) {
        const logs = getResultLogs(result);
        if (!logs.length) return '';
        const hasFail = logs.some(entry => entry && entry.status === 'fail');
        const items = logs.map((entry, index) => {
            const status = LOG_STATUS_LABELS[entry.status] ? entry.status : 'info';
            const icon = status === 'ok' ? '✓' : status === 'fail' ? '✕' : status === 'warn' ? '!' : '·';
            const step = STAGE_LABELS[entry.step] || entry.step || ('Bước ' + (index + 1));
            const duration = Number(entry.duration_ms);
            const durationHtml = Number.isFinite(duration)
                ? '<span class="mailtest-log-ms">' + duration + ' ms</span>'
                : '';
            return '<li class="mailtest-log-item is-' + status + '">' +
                '<span class="mailtest-log-icon" aria-hidden="true">' + icon + '</span>' +
                '<div class="mailtest-log-body">' +
                '<div class="mailtest-log-head">' +
                '<span class="mailtest-log-step">' + escapeHtml(step) + '</span>' +
                durationHtml +
                '</div>' +
                '<div class="mailtest-log-text">' +
                escapeHtml(entry.message || LOG_STATUS_LABELS[status]) +
                '</div>' +
                '</div></li>';
        }).join('');

        return '<details class="mailtest-log" open>' +
            '<summary>Nhật ký từng bước <span class="mailtest-log-count">' + logs.length + ' bước</span>' +
            (hasFail ? '<span class="mailtest-log-has-fail">có lỗi</span>' : '') +
            '</summary>' +
            '<ol class="mailtest-log-list">' + items + '</ol>' +
            '</details>';
    }

    function renderResultCard(result) {
        const ok = !!result.ok;
        const protocol = String(result.protocol || '').toUpperCase();
        const details = result.details || {};
        const security = result.security || details.security || '';
        const securityLabel = SECURITY_LABELS[security] || security;
        const stageLabel = STAGE_LABELS[result.stage] || result.stage || '';
        const duration = Number(result.duration_ms);
        const meta = [
            securityLabel,
            stageLabel,
            Number.isFinite(duration) ? duration + ' ms' : ''
        ].filter(Boolean).join(' · ');
        const endpoint = String(result.server || '') + ':' + String(result.port || details.port || '');
        const rows = detailRows(result);
        const rowsHtml = rows.length
            ? '<div class="mailtest-result-details">' + rows.map(row =>
                '<div class="mailtest-detail-row"><span>' + escapeHtml(row[0]) + '</span><code>' +
                escapeHtml(row[1]) + '</code></div>'
            ).join('') + '</div>'
            : '';
        const logsHtml = renderLogSteps(result);

        return '<article class="mailtest-result-card ' + (ok ? 'is-ok' : 'is-fail') + '">' +
            '<div class="mailtest-result-head">' +
            '<div class="mailtest-result-name">' +
            '<span class="mailtest-proto">' + escapeHtml(protocol) + '</span>' +
            '<span class="mailtest-endpoint">' + escapeHtml(endpoint) + '</span>' +
            '</div>' +
            '<span class="mailtest-status ' + (ok ? 'ok' : 'fail') + '">' +
            (ok ? 'Thành công' : 'Thất bại') + '</span>' +
            '</div>' +
            '<div class="mailtest-result-meta">' + escapeHtml(meta) + '</div>' +
            '<div class="mailtest-result-message">' + escapeHtml(result.message || '') + '</div>' +
            rowsHtml +
            logsHtml +
            '</article>';
    }

    function renderResults(data) {
        const results = Array.isArray(data.results) ? data.results : [];
        const resultsBox = byId('mailTestResults');
        if (!resultsBox) return;
        if (!results.length) {
            resultsBox.innerHTML = emptyState('Không có kết quả trả về.');
            return;
        }

        const reportedOk = Number(data.ok_count);
        const okCount = Number.isFinite(reportedOk)
            ? reportedOk
            : results.filter(item => item && item.ok).length;
        const total = Number.isFinite(Number(data.total)) ? Number(data.total) : results.length;
        const stateClass = okCount === total ? 'is-ok' : (okCount === 0 ? 'is-fail' : 'is-warn');

        resultsBox.innerHTML =
            '<div class="mailtest-summary-card ' + stateClass + '">' +
            '<div class="mailtest-summary-title">Tổng kết</div>' +
            '<div class="mailtest-summary-score">' + okCount + '/' + total + '</div>' +
            '<div class="mailtest-summary-sub">' + escapeHtml(data.server || '') +
            ' · ' + escapeHtml(data.username || '') + '</div>' +
            '</div>' +
            '<div class="mailtest-result-grid">' + results.map(renderResultCard).join('') + '</div>';
    }

    async function mailTestSubmit(event) {
        if (event) event.preventDefault();

        const serverEl = byId('mailTestServer');
        const usernameEl = byId('mailTestUsername');
        const passwordEl = byId('mailTestPassword');
        const server = serverEl ? serverEl.value.trim() : '';
        const username = usernameEl ? usernameEl.value.trim() : '';
        const password = passwordEl ? passwordEl.value : '';

        if (!server) {
            setMessage('error', 'Vui lòng nhập server name.');
            if (serverEl) serverEl.focus();
            return;
        }
        if (!username) {
            setMessage('error', 'Vui lòng nhập username.');
            if (usernameEl) usernameEl.focus();
            return;
        }
        if (!password) {
            setMessage('error', 'Vui lòng nhập password.');
            if (passwordEl) passwordEl.focus();
            return;
        }

        const protocols = collectProtocols();
        if (!protocols) return;
        if (!PROTOCOLS.some(protocol => protocols[protocol].enabled)) {
            setMessage('error', 'Chọn ít nhất một giao thức để test (SMTP, POP hoặc IMAP).');
            return;
        }

        const sendEl = byId('mailTestSmtpSend');
        const toEl = byId('mailTestSmtpTo');
        const smtpSend = !!(sendEl && sendEl.checked);
        const smtpTo = toEl ? toEl.value.trim() : '';
        if (protocols.smtp.enabled && smtpSend && !smtpTo) {
            setMessage('error', 'Vui lòng nhập địa chỉ To cho email test SMTP.');
            if (toEl) toEl.focus();
            return;
        }

        if (controller) {
            try { controller.abort(); } catch (error) { /* ignore */ }
        }
        const currentController = new AbortController();
        controller = currentController;

        setMessage('', '');
        setLoading(true);

        try {
            const response = await fetch('/api/mail-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    server,
                    username,
                    password,
                    protocols,
                    smtp: {
                        send: smtpSend,
                        to: smtpTo || username
                    }
                }),
                signal: currentController.signal
            });

            let data = {};
            try {
                data = await response.json();
            } catch (error) {
                throw new Error('Server trả về dữ liệu không hợp lệ.');
            }
            if (controller !== currentController) return;
            if (!response.ok || data.error) {
                throw new Error(data.error || ('HTTP ' + response.status));
            }

            renderResults(data);
            const okCount = Number(data.ok_count);
            const total = Number(data.total);
            if (Number.isFinite(okCount) && Number.isFinite(total) && okCount === total) {
                setMessage('success', 'Tất cả ' + total + ' giao thức đều thành công.');
            } else {
                setMessage('info', (Number.isFinite(okCount) ? okCount : 0) + '/' +
                    (Number.isFinite(total) ? total : 0) + ' giao thức thành công. Xem chi tiết bên cạnh.');
            }
        } catch (error) {
            if (error && error.name === 'AbortError') return;
            if (controller !== currentController) return;
            setMessage('error', 'Lỗi: ' + (error.message || error));
            const resultsBox = byId('mailTestResults');
            if (resultsBox) {
                resultsBox.innerHTML = '<div class="mailtest-error-state">Không thể hoàn tất test. Kiểm tra thông báo lỗi phía trên.</div>';
            }
        } finally {
            if (controller === currentController) {
                controller = null;
                setLoading(false);
            }
        }
    }

    function mailTestProtocolToggled(protocol) {
        syncProtocolCard(protocol);
    }

    function mailTestSecurityChanged(protocol) {
        const securityEl = byId('mailTest' + cap(protocol) + 'Security');
        const portEl = byId('mailTest' + cap(protocol) + 'Port');
        const defaults = DEFAULT_PORTS[protocol];
        if (!securityEl || !portEl || !defaults) return;
        const nextPort = defaults[securityEl.value];
        if (nextPort) portEl.value = nextPort;
    }

    function mailTestSyncFrom() {
        syncFrom();
    }

    function mailTestUseUsernameAsTo() {
        const username = byId('mailTestUsername');
        const to = byId('mailTestSmtpTo');
        const button = byId('mailTestUseUsernameBtn');
        if (!to) return;

        const useUsername = !!(button && button.dataset.mode === 'username');
        if (!useUsername) {
            if (!username || !username.value.trim()) {
                setMessage('error', 'Nhập username trước khi dùng làm địa chỉ To.');
                if (username) username.focus();
                return;
            }
            to.value = username.value.trim();
        } else {
            to.value = DEFAULT_TO;
        }
        syncToButton();
        setMessage('', '');
    }

    function mailTestSyncTo() {
        syncToButton();
    }

    function mailTestTogglePassword() {
        const input = byId('mailTestPassword');
        const button = byId('mailTestTogglePassword');
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        if (button) {
            button.textContent = show ? 'Ẩn' : 'Hiện';
            button.setAttribute('aria-label', show ? 'Ẩn mật khẩu' : 'Hiện mật khẩu');
        }
    }

    function mailTestSyncSmtpSend() {
        syncSmtpSend();
    }

    function mailTestReset() {
        if (controller) {
            try { controller.abort(); } catch (error) { /* ignore */ }
            controller = null;
        }

        const server = byId('mailTestServer');
        const username = byId('mailTestUsername');
        const password = byId('mailTestPassword');
        const toggle = byId('mailTestTogglePassword');
        if (server) server.value = '';
        if (username) username.value = '';
        if (password) {
            password.value = '';
            password.type = 'password';
        }
        if (toggle) {
            toggle.textContent = 'Hiện';
            toggle.setAttribute('aria-label', 'Hiện mật khẩu');
        }

        const smtpFrom = byId('mailTestSmtpFrom');
        const smtpTo = byId('mailTestSmtpTo');
        const smtpSend = byId('mailTestSmtpSend');
        const toToggle = byId('mailTestUseUsernameBtn');
        if (smtpFrom) smtpFrom.value = '';
        if (smtpTo) smtpTo.value = DEFAULT_TO;
        if (smtpSend) smtpSend.checked = true;
        if (toToggle) toToggle.dataset.mode = 'default';

        const enabled = { smtp: true, pop: false, imap: false };
        for (const protocol of PROTOCOLS) {
            const enabledEl = byId('mailTest' + cap(protocol) + 'Enabled');
            const portEl = byId('mailTest' + cap(protocol) + 'Port');
            const securityEl = byId('mailTest' + cap(protocol) + 'Security');
            if (enabledEl) enabledEl.checked = enabled[protocol];
            if (securityEl) securityEl.value = 'ssl';
            if (portEl) portEl.value = DEFAULT_PORTS[protocol].ssl;
            syncProtocolCard(protocol);
        }

        syncFrom();
        syncSmtpSend();
        setMessage('', '');
        setLoading(false);
        const results = byId('mailTestResults');
        if (results) {
            results.innerHTML = emptyState('Chưa có kết quả. Nhập thông tin và bấm Test kết nối.');
        }
        if (server) server.focus();
    }

    function init() {
        PROTOCOLS.forEach(syncProtocolCard);
        const passwordToggle = byId('mailTestTogglePassword');
        if (passwordToggle) passwordToggle.addEventListener('click', mailTestTogglePassword);
        syncFrom();
        syncSmtpSend();
        syncToButton();
    }

    window.mailTestSubmit = mailTestSubmit;
    window.mailTestReset = mailTestReset;
    window.mailTestProtocolToggled = mailTestProtocolToggled;
    window.mailTestSecurityChanged = mailTestSecurityChanged;
    window.mailTestSyncFrom = mailTestSyncFrom;
    window.mailTestSyncTo = mailTestSyncTo;
    window.mailTestUseUsernameAsTo = mailTestUseUsernameAsTo;
    window.mailTestTogglePassword = mailTestTogglePassword;
    window.mailTestSyncSmtpSend = mailTestSyncSmtpSend;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
