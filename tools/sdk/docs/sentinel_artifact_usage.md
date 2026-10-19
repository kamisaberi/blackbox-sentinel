# Recompile blackbox-sentinel binaries
cd ~/blackbox-sentinel/build
cmake ..
make -j$(nproc)
sudo make install

# 1. Login with JWT token (exchanges JWT for ary_hub_live_... API key)
sentinel-ctl login --jwt YOUR_JWT_TOKEN_HERE

# 2. Check authenticated identity
sentinel-ctl whoami

# 3. Publish artifact without passing --token flag (auto-loads from credentials.json!)
sentinel-artifact publish plant_safety_filter.spkg



Here is the URL normalization solution for **`sentinel_artifact.cpp`**.

### How It Works

Instead of requiring the full path `https://backend.aryorithm.com/api/v1/hub`, we added a smart URL normalizer (`normalize_publish_endpoint`). 

Now you can pass **just the base domain or host**, and it automatically appends `/api/v1/hub/publish`:

```text
========================================================================================================
                          SMART HUB URL NORMALIZATION EXAMPLES
========================================================================================================
 What You Pass in `--hub-url`                   Targeted Intake Endpoint
────────────────────────────────────────────────────────────────────────────────────────────────────────
 (Default: omitted)                            ──> https://backend.aryorithm.com/api/v1/hub/publish
 http://localhost:8000                         ──> http://localhost:8000/api/v1/hub/publish
 http://127.0.0.1:8000                         ──> http://127.0.0.1:8000/api/v1/hub/publish
 https://backend.aryorithm.com                 ──> https://backend.aryorithm.com/api/v1/hub/publish
 https://backend.aryorithm.com/api/v1/hub      ──> https://backend.aryorithm.com/api/v1/hub/publish
========================================================================================================
```

---

### Now You Can Use Any Short Host Form!

1. **Production Default:**
   ```bash
   sentinel-artifact publish plant_safety_filter.spkg
   # Targets: https://backend.aryorithm.com/api/v1/hub/publish
   ```

2. **Local Dev Server (Just pass host and port):**
   ```bash
   sentinel-artifact publish plant_safety_filter.spkg --hub-url http://localhost:8000
   # Targets: http://localhost:8000/api/v1/hub/publish
   ```

3. **Short IP or Domain:**
   ```bash
   sentinel-artifact publish plant_safety_filter.spkg --hub-url 127.0.0.1:8000
   # Targets: http://127.0.0.1:8000/api/v1/hub/publish
   ```