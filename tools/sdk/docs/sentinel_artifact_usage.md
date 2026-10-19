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