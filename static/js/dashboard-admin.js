import { auth } from "./firebase-init.js";

import {
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

const ADMIN_EMAILS = ["ans0225971@ju.edu.jo"];

const STATUS_OPTIONS = [
    ["pending_review", "Pending Review"],
    ["confirmed_malicious", "Confirmed Malicious"],
    ["ignored", "Ignored"],
    ["false_positive", "False Positive"],
    ["under_investigation", "Under Investigation"]
];

function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function isKnownAdminEmail(email) {
    return ADMIN_EMAILS.includes(normalizeEmail(email));
}

document.addEventListener("DOMContentLoaded", () => {
    const normalDashboardView = document.getElementById("normal-dashboard-view");
    const adminDashboardView = document.getElementById("admin-dashboard-view");

    const adminTypeFilter = document.getElementById("admin-type-filter");
    const refreshReportsBtn = document.getElementById("refresh-reports-btn");
    const downloadCsvBtn = document.getElementById("download-csv-btn");
    const reportsTableBody = document.getElementById("reports-table-body");
    const adminMessage = document.getElementById("admin-message");

    const totalReportsEl = document.getElementById("admin-total-reports");
    const pendingReportsEl = document.getElementById("admin-pending-reports");
    const confirmedReportsEl = document.getElementById("admin-confirmed-reports");
    const ignoredReportsEl = document.getElementById("admin-ignored-reports");

    let isAdmin = false;

    function showAdminDashboard() {
        normalDashboardView?.classList.add("hidden");
        adminDashboardView?.classList.remove("hidden");
    }

    function showNormalDashboard() {
        normalDashboardView?.classList.remove("hidden");
        adminDashboardView?.classList.add("hidden");
    }

    function showMessage(message, type = "error") {
        if (!adminMessage) return;
        adminMessage.textContent = message;
        adminMessage.className = `report-message ${type}`;
    }

    function clearMessage() {
        if (!adminMessage) return;
        adminMessage.textContent = "";
        adminMessage.className = "report-message";
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    async function syncBackendSession(user) {
        const idToken = await user.getIdToken(); 

        try {
            await fetch("/api/auth/session", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${idToken}`
                }
            });
        } catch (error) {
            console.error("Backend session sync failed:", error);
        }

        return idToken;
    }

    async function getRole(user) {
        let idToken = await syncBackendSession(user);

        try {
            let response = await fetch("/api/auth/role", {
                headers: {
                    Authorization: `Bearer ${idToken}`
                }
            });

            // Retry logic: Force refresh if token is rejected
            if (response.status === 401) {
                idToken = await user.getIdToken(true);
                response = await fetch("/api/auth/role", {
                    headers: {
                        Authorization: `Bearer ${idToken}`
                    }
                });
            }

            if (!response.ok) {
                return {
                    is_admin: isKnownAdminEmail(user.email)
                };
            }

            const data = await response.json();

            return {
                ...data,
                is_admin: Boolean(data.is_admin) || isKnownAdminEmail(user.email)
            };
        } catch {
            return {
                is_admin: isKnownAdminEmail(user.email)
            };
        }
    }

    function buildStatusDropdown(report) {
        const options = STATUS_OPTIONS.map(([value, label]) => {
            const selected = value === report.status ? "selected" : "";
            return `<option value="${value}" ${selected}>${label}</option>`;
        }).join("");

        return `
            <select
                class="status-dropdown"
                data-collection="${escapeHtml(report.collection_name)}"
                data-document-id="${escapeHtml(report.document_id)}"
            >
                ${options}
            </select>
        `;
    }

    function updateStats(reports) {
        const total = reports.length;
        const pending = reports.filter(r => r.status === "pending_review").length;
        const confirmed = reports.filter(r => r.status === "confirmed_malicious").length;
        const ignored = reports.filter(r =>
            r.status === "ignored" || r.status === "false_positive"
        ).length;

        if (totalReportsEl) totalReportsEl.textContent = total;
        if (pendingReportsEl) pendingReportsEl.textContent = pending;
        if (confirmedReportsEl) confirmedReportsEl.textContent = confirmed;
        if (ignoredReportsEl) ignoredReportsEl.textContent = ignored;
    }

    function updateStatsFromDOM() {
        const dropdowns = document.querySelectorAll('.status-dropdown');
        let total = dropdowns.length;
        let pending = 0;
        let confirmed = 0;
        let ignored = 0;

        dropdowns.forEach(dd => {
            const val = dd.value;
            if (val === "pending_review") pending++;
            else if (val === "confirmed_malicious") confirmed++;
            else if (val === "ignored" || val === "false_positive") ignored++;
        });

        if (totalReportsEl) totalReportsEl.textContent = total;
        if (pendingReportsEl) pendingReportsEl.textContent = pending;
        if (confirmedReportsEl) confirmedReportsEl.textContent = confirmed;
        if (ignoredReportsEl) ignoredReportsEl.textContent = ignored;
    }

    function renderReports(reports) {
        updateStats(reports);

        if (!reports || reports.length === 0) {
            reportsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-table">No reports found.</td>
                </tr>
            `;
            return;
        }

        reportsTableBody.innerHTML = reports.map(report => `
            <tr>
                <td>${escapeHtml(report.indicator_label || report.indicator_type)}</td>

                <td class="indicator-cell" title="${escapeHtml(report.indicator_value)}">
                    ${escapeHtml(report.indicator_value)}
                </td>

                <td>
                    <span class="report-count-badge">${escapeHtml(report.report_count)}</span>
                </td>

                <td>${buildStatusDropdown(report)}</td>

                <td>${escapeHtml(report.reported_by_email || report.reported_by)}</td>

                <td>${escapeHtml(report.timestamp)}</td>
            </tr>
        `).join("");

        document.querySelectorAll(".status-dropdown").forEach(dropdown => {
            dropdown.addEventListener("change", async () => {
                await updateReportStatus(dropdown);
            });
        });
    }

    async function loadReports() {
        if (!isAdmin || !reportsTableBody) return;

        const user = auth.currentUser;
        if (!user) return;
        let idToken = await user.getIdToken(); 

        clearMessage();

        reportsTableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-table">Loading reports...</td>
            </tr>
        `;

        try {
            const indicatorType = adminTypeFilter?.value || "all";

            let response = await fetch(`/api/reports?indicator_type=${encodeURIComponent(indicatorType)}`, {
                headers: {
                    Authorization: `Bearer ${idToken}`
                }
            });

            // Retry logic: Force token refresh if rejected
            if (response.status === 401) {
                console.warn("Token rejected. Forcing refresh...");
                idToken = await user.getIdToken(true);
                response = await fetch(`/api/reports?indicator_type=${encodeURIComponent(indicatorType)}`, {
                    headers: {
                        Authorization: `Bearer ${idToken}`
                    }
                });
            }

            const text = await response.text();

            if (response.status === 401) {
                reportsTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-table">
                            Authentication token was rejected. Log out and log in again.
                        </td>
                    </tr>
                `;
                showMessage("Authentication failed. Log out and log in again.", "error");
                return;
            }

            if (response.status === 403) {
                reportsTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-table">
                            Admin access denied. Check ADMIN_EMAILS.
                        </td>
                    </tr>
                `;
                showMessage("You are logged in, but the backend does not allow this email as admin.", "error");
                return;
            }

            if (!response.ok) {
                console.error("Reports API error:", text);
                throw new Error("Failed to load reports.");
            }

            const data = JSON.parse(text);
            renderReports(data.reports || []);
        } catch (error) {
            console.error(error);
            showMessage("Failed to load reports. Check terminal and browser console.", "error");
        }
    }

    async function updateReportStatus(dropdown) {
        const user = auth.currentUser;
        if (!user) return;
        let idToken = await user.getIdToken(); 

        const collectionName = dropdown.dataset.collection;
        const documentId = dropdown.dataset.documentId;
        const status = dropdown.value;
        const originalValue = dropdown.dataset.previousValue || dropdown.value;

        dropdown.disabled = true;

        try {
            let response = await fetch(
                `/api/reports/${encodeURIComponent(collectionName)}/${encodeURIComponent(documentId)}/status`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${idToken}`
                    },
                    body: JSON.stringify({ status, review_notes: "" })
                }
            );

            // Retry logic: Force token refresh if rejected
            if (response.status === 401) {
                idToken = await user.getIdToken(true);
                response = await fetch(
                    `/api/reports/${encodeURIComponent(collectionName)}/${encodeURIComponent(documentId)}/status`,
                    {
                        method: "PATCH",
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${idToken}`
                        },
                        body: JSON.stringify({ status, review_notes: "" })
                    }
                );
            }

            const text = await response.text();

            if (!response.ok) {
                console.error("Status update error:", text);
                throw new Error("Status update failed.");
            }

            showMessage("Status updated successfully.", "success");
            dropdown.dataset.previousValue = status;
            updateStatsFromDOM();

        } catch (error) {
            console.error(error);
            showMessage("Failed to update status. Reverting change.", "error");
            dropdown.value = originalValue; 
        } finally {
            dropdown.disabled = false;
        }
    }

    async function downloadCsv() {
        const user = auth.currentUser;
        if (!user) return;
        let idToken = await user.getIdToken(); 

        try {
            const indicatorType = adminTypeFilter?.value || "all";

            let response = await fetch(`/api/reports/export.csv?indicator_type=${encodeURIComponent(indicatorType)}`, {
                headers: {
                    Authorization: `Bearer ${idToken}`
                }
            });

            // Retry logic: Force token refresh if rejected
            if (response.status === 401) {
                idToken = await user.getIdToken(true);
                response = await fetch(`/api/reports/export.csv?indicator_type=${encodeURIComponent(indicatorType)}`, {
                    headers: {
                        Authorization: `Bearer ${idToken}`
                    }
                });
            }

            const text = await response.clone().text();

            if (!response.ok) {
                console.error("CSV API error:", text);
                throw new Error("CSV export failed.");
            }

            const blob = await response.blob();
            const downloadUrl = URL.createObjectURL(blob);

            const link = document.createElement("a");
            link.href = downloadUrl;
            link.download = "reported_indicators.csv";
            document.body.appendChild(link);
            link.click();
            link.remove();

            URL.revokeObjectURL(downloadUrl);
        } catch (error) {
            console.error(error);
            showMessage("Failed to download CSV.", "error");
        }
    }

    refreshReportsBtn?.addEventListener("click", loadReports);
    adminTypeFilter?.addEventListener("change", loadReports);
    downloadCsvBtn?.addEventListener("click", downloadCsv);

    onAuthStateChanged(auth, async (user) => {
        if (!user) {
            isAdmin = false;
            showNormalDashboard();
            return;
        }

        if (isKnownAdminEmail(user.email)) {
            isAdmin = true;
            showAdminDashboard();
        }

        const role = await getRole(user);
        isAdmin = Boolean(role.is_admin);

        if (isAdmin) {
            showAdminDashboard();
            await loadReports();
        } else {
            showNormalDashboard();
        }
    });
});