"use strict";

const REFRESH_INTERVAL = 5000;


function escapeHtml(value) {

    const text = String(
        value === null || value === undefined
            ? ""
            : value
    );

    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function formatNumber(value) {

    const number = Number(value || 0);

    return number.toLocaleString();
}


function formatBytes(value) {

    let bytes = Number(value || 0);

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(
        bytes /
        (1024 * 1024 * 1024)
    ).toFixed(1)} GB`;
}


function severityClass(severity) {

    const normalized = String(
        severity || "INFO"
    ).toUpperCase();

    return `severity severity-${normalized.toLowerCase()}`;
}


function updateSummary(state) {

    const summary = state.summary || {};

    document.getElementById(
        "devices-count"
    ).textContent = formatNumber(
        summary.devices_discovered
    );

    document.getElementById(
        "ports-count"
    ).textContent = formatNumber(
        summary.open_ports
    );

    document.getElementById(
        "alerts-count"
    ).textContent = formatNumber(
        summary.network_alerts
    );

    document.getElementById(
        "high-alerts-count"
    ).textContent = formatNumber(
        summary.high_severity_alerts
    );

    document.getElementById(
        "traffic-count"
    ).textContent = formatNumber(
        summary.traffic_packets
    );

    document.getElementById(
        "traffic-bytes"
    ).textContent = formatBytes(
        summary.traffic_bytes
    );

    document.getElementById(
        "traffic-packets-small"
    ).textContent = formatNumber(
        summary.traffic_packets
    );

    document.getElementById(
        "traffic-bytes-small"
    ).textContent = formatBytes(
        summary.traffic_bytes
    );
}


function updateAssessment(state) {

    const assessment =
        state.assessment || {};

    const mode =
        document.getElementById(
            "assessment-mode"
        );

    if (
        assessment.authorized_assessment_only
    ) {
        mode.textContent =
            "AUTHORIZED NETWORKS ONLY";
    } else {
        mode.textContent =
            "ASSESSMENT MODE WARNING";
    }

    document.getElementById(
        "network-name"
    ).textContent =
        assessment.network ||
        "No discovery";
}


function updateDevices(state) {

    const tbody =
        document.getElementById(
            "devices-table"
        );

    const devices =
        state.devices || [];

    if (!devices.length) {

        tbody.innerHTML = `
            <tr>
                <td
                    colspan="5"
                    class="empty-state"
                >
                    No network discovery data
                    available.
                </td>
            </tr>
        `;

        return;
    }

    tbody.innerHTML = devices
        .map(device => {

            const response =
                device.response_time === null ||
                device.response_time === undefined
                    ? "N/A"
                    : `${device.response_time} ms`;

            return `
                <tr>
                    <td>
                        ${escapeHtml(device.ip)}
                    </td>

                    <td>
                        ${escapeHtml(device.hostname)}
                    </td>

                    <td>
                        ${escapeHtml(device.mac)}
                    </td>

                    <td>
                        ${escapeHtml(device.status)}
                    </td>

                    <td>
                        ${escapeHtml(response)}
                    </td>
                </tr>
            `;
        })
        .join("");
}


function updatePorts(state) {

    const container =
        document.getElementById(
            "ports-list"
        );

    const ports =
        state.ports || [];

    const openPorts =
        ports.filter(
            item =>
                String(item.state).toUpperCase()
                === "OPEN"
        );

    if (!openPorts.length) {

        container.innerHTML = `
            <div class="empty-state">
                No open ports available.
            </div>
        `;

        return;
    }

    container.innerHTML = openPorts
        .map(port => {

            return `
                <div class="list-item">

                    <div class="list-item-title">
                        Port ${escapeHtml(port.port)}
                    </div>

                    <div class="list-item-meta">
                        ${escapeHtml(
                            port.service || "Unknown"
                        )}
                    </div>

                </div>
            `;
        })
        .join("");
}


function updateAlerts(state) {

    const tbody =
        document.getElementById(
            "alerts-table"
        );

    const alerts =
        state.alerts || [];

    if (!alerts.length) {

        tbody.innerHTML = `
            <tr>
                <td
                    colspan="4"
                    class="empty-state"
                >
                    No IDS alerts available.
                </td>
            </tr>
        `;

        return;
    }

    tbody.innerHTML = alerts
        .slice()
        .reverse()
        .map(alert => {

            return `
                <tr>

                    <td>
                        <span class="${severityClass(
                            alert.severity
                        )}">
                            ${escapeHtml(
                                alert.severity
                            )}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(
                            alert.type
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            alert.source
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            alert.timestamp
                        )}
                    </td>

                </tr>
            `;
        })
        .join("");
}


function updateTraffic(state) {

    const container =
        document.getElementById(
            "traffic-bars"
        );

    const traffic =
        state.traffic || {};

    const protocols =
        traffic.protocols || {};

    const entries =
        Object.entries(protocols);

    if (!entries.length) {

        container.innerHTML = `
            <div class="empty-state">
                No traffic analysis performed.
            </div>
        `;

        return;
    }

    const maximum =
        Math.max(
            ...entries.map(
                ([, value]) =>
                    Number(value || 0)
            ),
            1
        );

    container.innerHTML = entries
        .sort(
            ([, a], [, b]) =>
                Number(b || 0) -
                Number(a || 0)
        )
        .map(([protocol, count]) => {

            const numeric =
                Number(count || 0);

            const width =
                Math.max(
                    2,
                    (numeric / maximum) * 100
                );

            return `
                <div class="traffic-row">

                    <span class="traffic-label">
                        ${escapeHtml(protocol)}
                    </span>

                    <div class="traffic-track">
                        <div
                            class="traffic-fill"
                            style="width: ${width}%"
                        ></div>
                    </div>

                    <span class="traffic-value">
                        ${formatNumber(numeric)}
                    </span>

                </div>
            `;
        })
        .join("");
}


function updateTopology(state) {

    const topology =
        state.topology || {};

    const image =
        document.getElementById(
            "topology-image"
        );

    const empty =
        document.getElementById(
            "topology-empty"
        );

    const status =
        document.getElementById(
            "topology-status"
        );

    document.getElementById(
        "topology-nodes"
    ).textContent =
        formatNumber(topology.nodes);

    document.getElementById(
        "topology-connections"
    ).textContent =
        formatNumber(topology.connections);

    if (
        topology.available &&
        topology.image_available
    ) {

        image.style.display = "block";

        empty.style.display = "none";

        status.textContent =
            "Available";

        image.src =
            `/topology-image?t=${Date.now()}`;

    } else {

        image.style.display = "none";

        empty.style.display = "block";

        status.textContent =
            "Not generated";
    }
}


function updateFirewall(state) {

    const container =
        document.getElementById(
            "firewall-list"
        );

    const findings =
        state.firewall_findings || [];

    if (!findings.length) {

        container.innerHTML = `
            <div class="empty-state">
                No firewall analysis performed.
            </div>
        `;

        return;
    }

    container.innerHTML = findings
        .map(finding => {

            return `
                <div class="list-item">

                    <div>
                        <span class="${severityClass(
                            finding.severity
                        )}">
                            ${escapeHtml(
                                finding.severity
                            )}
                        </span>
                    </div>

                    <div class="list-item-title">
                        ${escapeHtml(
                            finding.title
                        )}
                    </div>

                    <div class="list-item-meta">
                        ${escapeHtml(
                            finding.recommendation
                        )}
                    </div>

                </div>
            `;
        })
        .join("");
}


function updateRefreshTime() {

    document.getElementById(
        "last-refresh"
    ).textContent =
        `Updated ${new Date().toLocaleTimeString()}`;
}


async function loadDashboard() {

    const status =
        document.getElementById(
            "connection-status"
        );

    const connectionText =
        document.getElementById(
            "connection-text"
        );

    try {

        const response =
            await fetch(
                "/api/state",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const state =
            await response.json();

        if (state.error) {
            throw new Error(
                state.error
            );
        }

        status.style.background =
            "var(--success)";

        connectionText.textContent =
            "Dashboard connected";

        updateSummary(state);
        updateAssessment(state);
        updateDevices(state);
        updatePorts(state);
        updateAlerts(state);
        updateTraffic(state);
        updateTopology(state);
        updateFirewall(state);
        updateRefreshTime();

    } catch (error) {

        console.error(
            "NETWATCH dashboard error:",
            error
        );

        status.style.background =
            "var(--danger)";

        connectionText.textContent =
            "Dashboard connection error";
    }
}


loadDashboard();

setInterval(
    loadDashboard,
    REFRESH_INTERVAL
);