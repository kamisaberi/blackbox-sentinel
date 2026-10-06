# Protocol Dissector & Plugin Loading Failures

`blackbox-sentinel` loads its 30 industrial protocol dissectors dynamically from `/usr/local/lib/sentinel-plugins/`. This guide resolves dynamic linker and ABI compatibility issues.

---

## 1. `dlopen` Shared Library Loading Errors

### Symptom
```text
[ERROR] PluginManager: Failed to load libsentinel_plugin_modbus.so: libmodbus.so.5: cannot open shared object file: No such file or directory
```

### Remediation
1. Verify that all runtime dependency libraries are installed on the host:
   ```bash
   ldd /usr/local/lib/sentinel-plugins/libsentinel_plugin_modbus.so
   ```
2. Update the dynamic linker cache:
   ```bash
   sudo ldconfig
   ```
3. If dependencies reside in non-standard directories, update `/etc/ld.so.conf.d/sentinel.conf` or specify:
   ```bash
   export LD_LIBRARY_PATH=/usr/local/lib/sentinel-deps:$LD_LIBRARY_PATH
   ```

---

## 2. ABI Version Mismatch

### Symptom
```text
[ERROR] PluginManager: Plugin libsentinel_plugin_s7comm.so ABI version mismatch: Expected 1.0.0-cxx20, Found 0.9.4
```

### Cause
The dissector shared object was compiled against an outdated header definition of `IDissectorPlugin.hpp`.

### Remediation
Recompile the plugin modules using the unified `sentinel-stack` installer:

```bash
cd /opt/sentinel-stack
sudo ./install.sh --rebuild-plugins
```

