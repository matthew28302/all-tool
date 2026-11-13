(function () {
    'use strict';

    function init() {
        if (typeof window.renderSSLResults !== 'function') {
            setTimeout(init, 50);
            return;
        }
        const original = window.renderSSLResults;
        window.renderSSLResults = function (data) {
            original(data);
            const portCheckEl = document.getElementById('sslPortCheckResults');
            if (!portCheckEl) return;
            const portChecks = Array.isArray(data && data.port_checks) ? data.port_checks : [];
            if (!portChecks.length) {
                portCheckEl.innerHTML = '<div class="chain-empty">Không có dữ liệu port</div>';
                return;
            }
            portCheckEl.innerHTML = '<div style="display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))">' +
                portChecks.map(function (item) {
                    const ok = !!item.ok && !!item.valid && !!item.matched;
                    const days = item.days_remaining !== null && item.days_remaining !== undefined ? item.days_remaining + ' ngày' : '-';
                    const validTo = item.valid_to ? formatCertDate(item.valid_to) : '-';
                    const issuer = item.issuer || '-';
                    const subject = item.subject || '-';
                    const mismatch = (item.ok && !item.matched)
                        ? '<div style="color:#b45309;font-size:0.75rem;margin-top:4px">Cert không khớp domain (subject: ' + escapeHtml(subject) + ')</div>'
                        : '';
                    const error = item.error
                        ? '<div style="color:#b91c1c;font-size:0.75rem;margin-top:4px">' + escapeHtml(item.error) + '</div>'
                        : '';
                    const border = ok ? '1px solid #86efac' : '1px solid #fecaca';
                    const bg = ok ? '#f0fdf4' : '#fef2f2';
                    return '<article style="padding:10px;border-radius:10px;border:' + border + ';background:' + bg + '">' +
                        '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px">' +
                            '<strong>Port ' + escapeHtml(item.port) + '</strong>' +
                            '<span style="padding:2px 8px;border-radius:999px;font-size:0.7rem;font-weight:800;color:' + (ok ? '#15803d' : '#b91c1c') + ';background:' + (ok ? '#dcfce7' : '#fee2e2') + '">' + (ok ? 'Valid' : 'Fail') + '</span>' +
                        '</div>' +
                        '<div style="margin-top:6px;font-size:0.78rem;color:#475569">' + escapeHtml(days) + ' · hết hạn ' + escapeHtml(validTo) + '</div>' +
                        '<div style="margin-top:4px;font-size:0.78rem;color:#334155;overflow-wrap:anywhere">Subject: ' + escapeHtml(subject) + '</div>' +
                        '<div style="margin-top:2px;font-size:0.75rem;color:#64748b;overflow-wrap:anywhere">Issuer: ' + escapeHtml(issuer) + '</div>' +
                        mismatch +
                        error +
                    '</article>';
                }).join('') +
            '</div>';
        };
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();