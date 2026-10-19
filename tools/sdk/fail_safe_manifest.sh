cd /tmp/plant_safty_filter

# 1. Read your public key into a variable
PUB_HEX=$(openssl pkey -pubin -in ./keys/ed25519_public.pem -raw -outform HEX 2>/dev/null || openssl pkey -pubin -in ./keys/ed25519_public.pem -outform DER | tail -c 32 | xxd -p -c 64 | tr -d ' \n\r')

# 2. Update manifest.json with "slug" and "author_public_key"
cat << EOF > manifest.json
{
  "id": "org.aryorithm.package.plant_safty_filter",
  "name": "plant_safty_filter",
  "slug": "plant_safty_filter",
  "version": "1.0.0",
  "tier": "wasm",
  "author": "Aryorithm Certified Developer",
  "author_public_key": "${PUB_HEX}",
  "target_protocol": "CUSTOM",
  "default_port": 502,
  "latency_sla_ns": 1500,
  "compliance": ["IEC-62443-4-2", "CMMC-SI.L2-3.14.1"]
}
EOF

# 3. Re-pack and publish!
sentinel-artifact pack .
mv plant_safty_filter.spkg plant_safety_filter.spkg
sentinel-artifact publish plant_safety_filter.spkg