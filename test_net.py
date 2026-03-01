"""Quick diagnostic script to test the network layer in isolation."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network import create_default_topology, Packet
from traffic_generator import NormalTrafficGenerator
import config

# Create topology
topo = create_default_topology()
print("Nodes:", list(topo.nodes.keys()))
print("Links:", list(topo.links.keys()))
print()

# Reset all link tick budgets
tick_ms = 100
for link in topo.links.values():
    link.reset_tick(tick_ms)
    print(f"  Link {link.node_a_id}->{link.node_b_id}: "
          f"BW={link.bandwidth_bps/1e6:.1f}Mbps, "
          f"tick_budget={link._tick_budget} bytes")

print()

# Generate a few packets from client1 to server
gen = NormalTrafficGenerator(src_ip="10.0.0.2", dst_ip="10.0.0.1")
packets = gen.generate_tick(1.0, tick_ms)
print(f"Generated {len(packets)} packets from client1")
total_bytes = sum(p.size for p in packets)
print(f"Total bytes: {total_bytes}")

delivered = 0
dropped = 0
for pkt in packets:
    result = topo.send_packet(pkt)
    if result:
        delivered += 1
    else:
        dropped += 1

print(f"Delivered: {delivered}, Dropped: {dropped}")
print(f"Delivery rate: {delivered/(delivered+dropped)*100:.1f}%")
print()

# Check link state after
for link_id, link in topo.links.items():
    print(f"  Link {link_id}: "
          f"fwd={link.packets_forwarded}, drop={link.packets_dropped}, "
          f"bytes_tick={link._bytes_this_tick}/{link._tick_budget}")
print()

# Try topology totals
print(f"Topology: sent={topo.total_packets_sent}, "
      f"delivered={topo.total_packets_delivered}, "
      f"dropped={topo.total_packets_dropped}")
