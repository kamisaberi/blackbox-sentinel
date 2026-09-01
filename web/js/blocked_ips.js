document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel eBPF Blocked IP Table Manager Initialized.");

    window.unblockIP = async function(ipAddress) {
        if (!confirm(`Are you sure you want to unblock IP ${ipAddress} from eBPF kernel drop table?`)) {
            return;
        }

        try {
            const response = await fetch('http://localhost:8443/api/v1/unblock-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: ipAddress })
            });

            if (response.ok) {
                alert(`IP ${ipAddress} successfully removed from eBPF drop map.`);
                location.reload();
            }
        } catch (err) {
            console.log("Unblock request sent for IP: " + ipAddress);
        }
    };
});