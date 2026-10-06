# Installation & Deployment Guide

This guide covers deploying `blackbox-sentinel` on bare-metal systems, configuring systemd daemons, or importing pre-built virtual appliance images (OVA / QCOW2).

---

## 1. Bare-Metal Package Installation (Ubuntu / Debian)

Aryorithm maintains signed `.deb` packages for enterprise subscribers:

```bash
# 1. Add Aryorithm GPG Signing Key
sudo curl -fsSL https://packages.aryorithm.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/aryorithm.gpg

# 2. Add Package Repository
echo "deb [signed-by=/usr/share/keyrings/aryorithm.gpg] https://packages.aryorithm.com/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/aryorithm.list

# 3. Install Sentinel Daemon and Dependencies
sudo apt-get update && sudo apt-get install -y blackbox-sentinel
```

---

## 2. Manual Source Compilation & Installation

If building from the unified `sentinel-stack` meta-installer:

```bash
cd /opt/sentinel-stack
sudo ./install.sh
```

Alternatively, build `blackbox-sentinel` individually:

```bash
cd blackbox-sentinel
mkdir build && cd build
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja -j$(nproc)
sudo ninja install
```

---

## 3. Systemd Service Deployment

Enable and start the daemon as an automated background service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinel
sudo systemctl start sentinel
```

Check real-time execution status:

```bash
sudo systemctl status sentinel
```

---

## 4. Virtual Appliance Import (OVA / QCOW2)

For fast deployment in virtualized environments:

### VMware vSphere / ESXi (OVA Import)
```bash
# Deploy using ovftool
ovftool --acceptAllEulas \
    --datastore="Datastore1" \
    --name="Blackbox-Sentinel-Edge-01" \
    --net:"VM Network"="Protected_OT_VLAN" \
    blackbox-sentinel-v-edge.ova \
    vi://root@esxi-host-01.internal/
```

### KVM / Proxmox (QCOW2 Import)
```bash
# Create VM and import disk image
qm create 200 --name sentinel-edge --memory 8192 --cores 4 --net0 virtio,bridge=vmbr0
qm importdisk 200 blackbox-sentinel-v-edge.qcow2 local-zfs
qm set 200 --scsihw virtio-scsi-pci --scsi0 local-zfs:vm-200-disk-0
qm set 200 --boot c --bootdisk scsi0
```

