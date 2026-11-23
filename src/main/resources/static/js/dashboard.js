// Small helpers for the LAMS pages. Every page also works without JavaScript.
document.addEventListener('DOMContentLoaded', function () {

    // Changing the status drop-down applies the filter straight away
    var status = document.getElementById('status');
    var form = document.getElementById('filter-form');
    if (status && form) {
        status.addEventListener('change', function () {
            form.submit();
        });
    }

    // Forms with data-confirm="..." ask before they are sent
    document.querySelectorAll('form[data-confirm]').forEach(function (f) {
        f.addEventListener('submit', function (event) {
            if (!window.confirm(f.getAttribute('data-confirm'))) {
                event.preventDefault();
            }
        });
    });

    // ---------- Countdown on the login page while blocked / locked ----------
    document.querySelectorAll('.countdown[data-seconds]').forEach(function (el) {
        var left = parseInt(el.getAttribute('data-seconds'), 10);
        var timer = setInterval(function () {
            left -= 1;
            if (left <= 0) {
                clearInterval(timer);
                var box = el.closest('.alert');
                if (box) {
                    box.className = 'alert alert-success';
                    box.textContent = 'You can sign in again now.';
                }
                var button = document.getElementById('login-button');
                if (button) {
                    button.disabled = false;
                }
                return;
            }
            var m = Math.floor(left / 60);
            var s = left % 60;
            el.textContent = m + ':' + (s < 10 ? '0' : '') + s;
        }, 1000);
    });

    // ---------- Live feed on the admin overview ----------
    var table = document.getElementById('feed-table');
    var body = document.getElementById('feed-body');
    var live = document.getElementById('live');
    if (!table || !body || !live) {
        return;
    }
    var lastId = parseInt(table.getAttribute('data-last-id') || '0', 10);
    var url = table.getAttribute('data-url');
    var MAX_ROWS = 40;

    function text(tag, value, className) {
        var el = document.createElement(tag);
        el.textContent = value;   // textContent: never interpreted as HTML
        if (className) {
            el.className = className;
        }
        return el;
    }

    function cell() {
        var td = document.createElement('td');
        for (var i = 0; i < arguments.length; i++) {
            td.appendChild(arguments[i]);
        }
        return td;
    }

    function rowFor(item) {
        var tr = document.createElement('tr');
        tr.className = 'fresh';
        tr.appendChild(cell(text('span', item.time)));

        var ipLink = text('a', item.ip, 'mono');
        ipLink.href = url.replace('/api/feed', '/ip') + '?ip=' + encodeURIComponent(item.ip);
        tr.appendChild(cell(ipLink, text('div', item.location, 'sub')));

        tr.appendChild(cell(text('span', item.email)));

        var label = text('span', item.outcome, 'label label-' + item.outcome.toLowerCase());
        var result = cell(label);
        if (item.simulated) {
            result.appendChild(document.createTextNode(' '));
            result.appendChild(text('span', 'SIMULATED', 'tag tag-sim'));
        }
        if (item.reason) {
            result.appendChild(text('div', item.reason, 'sub'));
        }
        tr.appendChild(result);
        tr.appendChild(cell(text('span', item.device)));
        return tr;
    }

    function setText(id, value) {
        var el = document.getElementById(id);
        if (el && value !== undefined) {
            el.textContent = value;
        }
    }

    function poll() {
        if (!live.checked) {
            return;
        }
        fetch(url + '?after=' + lastId, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                var empty = document.getElementById('feed-empty');
                if (data.items.length && empty) {
                    empty.remove();
                }
                // items are newest first; insert oldest first so the newest ends on top
                for (var i = data.items.length - 1; i >= 0; i--) {
                    body.insertBefore(rowFor(data.items[i]), body.firstChild);
                }
                while (body.rows.length > MAX_ROWS) {
                    body.deleteRow(body.rows.length - 1);
                }
                lastId = data.lastId;
                setText('stat-active-blocks', data.activeBlockedIps);
                setText('stat-active-locks', data.activeLocks);
                setText('stat-open-alerts', data.openAlerts);
                setText('stat-24h', data.attempts24h);
                setText('generated-at', data.generatedAt);
            })
            .catch(function () {
                // e.g. the session expired - stop quietly
                live.checked = false;
            });
    }

    setInterval(poll, 5000);
});
