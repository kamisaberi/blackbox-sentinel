### Usage & Testing Options

1. **Discover Public Key from Cloud:**
   ```bash
   ./sentinel --fetch-key http://127.0.0.1:8000/api/v1
   ```
2. **Self-Service Subscribe via Cloud:**
   ```bash
   ./sentinel --subscribe community http://127.0.0.1:8000/api/v1
   ```
3. **Zero-Touch Activate via Cloud (with JWT):**
   ```bash
   ./sentinel --activate http://127.0.0.1:8000/api/v1 "your_jwt_access_token_here"
   ```
4. **Air-Gapped Offline Run (No Cloud Required):**
   ```bash
   sudo ./sentinel /etc/sentinel/sentinel.yaml
   ```
   *(If offline, it automatically loads `/etc/sentinel/license.lic`, verifies the signature using the embedded public key in $< 50\,\mu\text{s}$, and degrades gracefully to Community Free if missing or expired).*