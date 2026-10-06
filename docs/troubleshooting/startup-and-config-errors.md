# Startup Failures & Configuration Diagnostics

This guide provides troubleshooting and remediation steps for daemon startup aborts, configuration parser errors, and file permission issues in `blackbox-sentinel`.

---

## 1. YAML Parser Failures & Inline Comment Bugs

### Symptom
```text
[FATAL] ConfigManager: Failed to parse /etc/sentinel/sentinel.yaml: bad conversion on line 14: '8443 # Port'
[FATAL] Uvicorn/REST: 400 Bad Request: Invalid HTTP request received
```

### Cause
Earlier versions of custom YAML parsers read inline comments (`# ...`) as part of the string or numeric literal, resulting in invalid port numbers or whitespace-corrupted endpoints.

### Remediation
1. Verify that `blackbox-sentinel` is updated to the latest build, which implements automated comment stripping before type coercion in `ConfigManager.cpp`.
2. Ensure clean separation between values and comments in `/etc/sentinel/sentinel.yaml`:
   ```yaml
   # Correct formatting:
   web_console:
     port: 8443
   ```
3. Run the configuration validation tool:
   ```bash
   sentinel --validate-config /etc/sentinel/sentinel.yaml
   ```

---

## 2. Missing Mandatory Sections

### Symptom
```text
[FATAL] ConfigManager: Missing mandatory section 'ai_runtime' or 'network'
[FATAL] ApplianceCore initialization aborted with error code -10
```

### Remediation
Ensure `/etc/sentinel/sentinel.yaml` includes all seven root configuration sections:
* `appliance`
* `network`
* `ai_runtime`
* `hardware_identity`
* `web_console`
* `nexus_uplink`
* `storage`

---

## 3. Cryptographic Key Permissions

### Symptom
```text
[ERROR] WebConsole: Could not load private key from /etc/sentinel/certs/server.key: Permission denied
```

### Remediation
Ensure certificate files are readable by the executing service user or group:

```bash
sudo chown root:sentinel /etc/sentinel/certs/server.key
sudo chmod 640 /etc/sentinel/certs/server.key
```

