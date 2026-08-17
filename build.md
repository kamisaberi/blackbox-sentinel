# 1. Run the appliance installer
sudo ./deploy/install_appliance.sh

# 2. Run the Sentinel Commercial Daemon
sudo ./build/sentinel







---


# =========================================================
# STEP 1: Compile & Install Layer 1 (xinfer-essential)
# =========================================================
cd /path/to/xinfer-essential
mkdir build && cd build
cmake .. -DXINFER_ENABLE_OPENVINO=ON -DXINFER_ENABLE_TENSORRT=ON
make -j$(nproc)
sudo make install
sudo ldconfig

# =========================================================
# STEP 2: Compile & Install Layer 2 (blackbox)
# =========================================================
cd /path/to/blackbox
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig

# =========================================================
# STEP 3: Compile & Launch Layer 3 (blackbox-sentinel)
# =========================================================
cd /path/to/blackbox-sentinel
sudo ./deploy/install_appliance.sh
sudo ./build/sentinel