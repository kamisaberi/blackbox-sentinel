class EBPFTableController {
    constructor() {
        this.tableBody = document.getElementById('ebpf-table-body');
        this.inputManualIP = document.getElementById('input-manual-ip');
        this.btnManualBlock = document.getElementById('btn-manual-block');

        this.btnManualBlock.addEventListener('click', () => {
            const ip = this.inputManualIP.value.trim();
            if (ip) {
                this.addBlockedRow(ip, 'Manual Administrator Drop');
                this.inputManualIP.value = '';
            }
        });
    }

    addBlockedRow(ip, reason) {
        const tr = document.createElement('tr');
        tr.id = `ip-${ip.replace(/\./g, '-')}`;
        tr.innerHTML = `
            <td style="color: #ef4444; font-weight: 700;">${ip}</td>
            <td>${new Date().toLocaleTimeString()} UTC</td>
            <td>${reason}</td>
            <td><span class="badge tag-critical">XDP_DROP</span></td>
            <td><button class="btn btn-sm btn-secondary" onclick="window.ebpfTable.unblock('${ip}')">1-CLICK UNBLOCK</button></td>
        `;
        this.tableBody.appendChild(tr);
    }

    async unblock(ip) {
        const row = document.getElementById(`ip-${ip.replace(/\./g, '-')}`);
        if (row) row.remove();
        await window.apiClient.unblockIP(ip);
    }
}

window.ebpfTable = new EBPFTableController();