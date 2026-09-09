document.addEventListener('DOMContentLoaded', () => {
    const reportDisplay = document.getElementById('report-text-display');
    const btnRefresh = document.getElementById('btn-view-report');
    const btnExportCMMC = document.getElementById('btn-export-cmmc');
    const btnExportCSV = document.getElementById('btn-export-pcap');

    async function loadCMMCReport() {
        if (!reportDisplay) return;

        // Visual button feedback while fetching
        if (btnRefresh) {
            btnRefresh.disabled = true;
            btnRefresh.innerText = "REFRESHING...";
        }

        try {
            // Use relative path + timestamp to bypass browser cache
            const url = `/api/v1/reports/cmmc?t=${Date.now()}`;
            const resp = await fetch(url, { cache: 'no-store' });

            if (resp.ok) {
                const text = await resp.text();
                reportDisplay.innerText = text;
            } else {
                reportDisplay.innerText = `Error loading report from server (HTTP ${resp.status}).`;
            }
        } catch (err) {
            console.error("Failed to fetch CMMC report:", err);
            reportDisplay.innerText = "Unable to reach Sentinel REST API at /api/v1/reports/cmmc";
        } finally {
            if (btnRefresh) {
                btnRefresh.disabled = false;
                btnRefresh.innerText = "REFRESH REPORT";
            }
        }
    }

    // Load immediately on page open
    loadCMMCReport();

    // Click handler for Refresh Report button
    if (btnRefresh) {
        btnRefresh.addEventListener('click', (e) => {
            e.preventDefault();
            loadCMMCReport();
        });
    }

    // 1-Click Download for CMMC TXT Report
    if (btnExportCMMC) {
        btnExportCMMC.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = `/api/v1/reports/cmmc?download=true&t=${Date.now()}`;
        });
    }

    // 1-Click Download for Forensics CSV Report
    if (btnExportCSV) {
        btnExportCSV.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = `/api/v1/reports/csv?t=${Date.now()}`;
        });
    }
});