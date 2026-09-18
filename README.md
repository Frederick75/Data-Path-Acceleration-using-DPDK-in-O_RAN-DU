

**Build and run**

Install the DPDK development package and verify pkg-config --modversion libdpdk works. Build with:

gcc -O3 -march=native -std=c11 \
    -Wall -Wextra \
    dpdk_oran_du.c \
    -o dpdk_oran_du \
    $(pkg-config --cflags --libs libdpdk)

Reserve hugepages, for example:

sudo sysctl -w vm.nr_hugepages=2048

Check the NIC:

sudo dpdk-devbind.py --status

Bind the fronthaul VF/NIC to VFIO, for example:

sudo dpdk-devbind.py \
    --bind=vfio-pci \
    0000:18:00.1

Then run with one RX core and one PHY worker:

sudo ./dpdk_oran_du \
    -l 2-3 \
    -n 4 \
    -- \
    --port 0 \
    --mtu 9600 \
    --promisc \
    --dump 20
