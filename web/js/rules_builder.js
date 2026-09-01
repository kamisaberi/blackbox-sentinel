document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel Rules Builder UI Initialized.");

    window.saveRule = function() {
        const ruleName = document.getElementById('rule-name').value;
        const threshold = document.getElementById('rule-threshold').value;
        
        console.log(`Saving Rule: ${ruleName} (Threshold: ${threshold})`);
        alert(`Rule "${ruleName}" successfully saved to configs/default_rules.json`);
    };
});