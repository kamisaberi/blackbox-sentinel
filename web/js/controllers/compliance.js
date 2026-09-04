document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-export-cmmc').addEventListener('click', () => {
        window.open('http://localhost:8443/cmmc_audit_report.txt', '_blank');
    });

    document.getElementById('btn-export-pcap').addEventListener('click', () => {
        alert("Exporting raw forensic audit CSV...");
    });
});