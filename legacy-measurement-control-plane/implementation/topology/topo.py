#!/usr/bin/env python3
"""
topology.py — Mininet topology with BMv2 simple_switch_grpc

Creates a leaf-spine network with 4 BMv2 switches and 8 hosts:

          [spine1 s1]----[spine2 s2]
           /    \\            /    \\
      [leaf1 s3] ------[leaf2 s4]
       / \\                  / \\
    h1  h2  h3  h4      h5  h6  h7  h8

Each switch runs simple_switch_grpc (BMv2 with P4Runtime gRPC).
MCP connects to these switches via P4Runtime to control measurement.

Usage:
    sudo python3 topology/topo.py [--p4json PATH]
"""

import argparse
import os
import signal
import subprocess
import sys
import time

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.link import TCLink


# Paths
DEFAULT_P4JSON = os.path.join(os.path.dirname(__file__),
                              '..', 'p4src', 'build', 'mcp_switch.json')

BMV2_SWITCH = 'simple_switch_grpc'

# Base ports
GRPC_PORT_BASE = 50051
THRIFT_PORT_BASE = 9090


class BMv2GrpcSwitch(Switch):
    """Mininet switch subclass that runs BMv2 simple_switch_grpc.

    Based on the p4lang/tutorials p4_mininet.py pattern.
    Each instance starts a simple_switch_grpc process with:
    - Unique device ID
    - Unique gRPC port for P4Runtime
    - Unique Thrift port for runtime CLI
    - The compiled P4 JSON loaded at startup
    """

    device_id_counter = 0

    def __init__(self, name, json_path=None, grpc_port=None,
                 thrift_port=None, device_id=None, log_dir='/tmp',
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.json_path = json_path or DEFAULT_P4JSON
        self.grpc_port = grpc_port or (GRPC_PORT_BASE + BMv2GrpcSwitch.device_id_counter)
        self.thrift_port = thrift_port or (THRIFT_PORT_BASE + BMv2GrpcSwitch.device_id_counter)
        if device_id is not None:
            self.device_id = device_id
        else:
            self.device_id = BMv2GrpcSwitch.device_id_counter
        BMv2GrpcSwitch.device_id_counter += 1
        self.log_dir = log_dir
        self.bmv2_proc = None

    def start(self, controllers):
        """Start the BMv2 simple_switch_grpc process."""
        # Build interface mapping: -i port@intf
        iface_args = []
        for port, intf in enumerate(self.intfList()):
            if intf.name == 'lo':
                continue
            iface_args.extend(['-i', f'{port}@{intf.name}'])

        log_file = os.path.join(self.log_dir, f'{self.name}.log')

        cmd = [
            BMV2_SWITCH,
            f'--device-id', str(self.device_id),
            *iface_args,
            f'--thrift-port', str(self.thrift_port),
            f'--log-file', log_file,
            f'--log-flush',
            '--',
            f'--grpc-server-addr', f'0.0.0.0:{self.grpc_port}',
            '--cpu-port', '255',
            self.json_path,
        ]

        info(f'  Starting {self.name}: gRPC={self.grpc_port}, '
             f'thrift={self.thrift_port}, device_id={self.device_id}\n')

        self.bmv2_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Give BMv2 time to start and bind ports
        time.sleep(1)

        if self.bmv2_proc.poll() is not None:
            stderr = self.bmv2_proc.stderr.read().decode()
            error(f'  ERROR: {self.name} failed to start!\n')
            error(f'    stderr: {stderr}\n')

    def stop(self, deleteIntfs=True):
        """Stop the BMv2 process."""
        if self.bmv2_proc and self.bmv2_proc.poll() is None:
            self.bmv2_proc.send_signal(signal.SIGTERM)
            try:
                self.bmv2_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.bmv2_proc.kill()
            info(f'  Stopped {self.name}\n')
        Switch.stop(self, deleteIntfs)


class MCPTopo(Topo):
    """
    Leaf-spine topology for MCP experiments.

    Switch roles (important for MCP allocation decisions):
        s1, s2: spine switches — high centrality, see all traffic
        s3, s4: leaf switches  — edge, see per-host traffic
    """

    def build(self, json_path=None):
        json_path = json_path or DEFAULT_P4JSON

        # Switches — each runs BMv2 simple_switch_grpc
        s1 = self.addSwitch('s1', cls=BMv2GrpcSwitch,
                            json_path=json_path, device_id=0,
                            grpc_port=50051, thrift_port=9090)
        s2 = self.addSwitch('s2', cls=BMv2GrpcSwitch,
                            json_path=json_path, device_id=1,
                            grpc_port=50052, thrift_port=9091)
        s3 = self.addSwitch('s3', cls=BMv2GrpcSwitch,
                            json_path=json_path, device_id=2,
                            grpc_port=50053, thrift_port=9092)
        s4 = self.addSwitch('s4', cls=BMv2GrpcSwitch,
                            json_path=json_path, device_id=3,
                            grpc_port=50054, thrift_port=9093)

        # Hosts — left rack (behind leaf1)
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='08:00:00:00:01:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='08:00:00:00:01:02')
        h3 = self.addHost('h3', ip='10.0.1.3/24', mac='08:00:00:00:01:03')
        h4 = self.addHost('h4', ip='10.0.1.4/24', mac='08:00:00:00:01:04')

        # Hosts — right rack (behind leaf2)
        h5 = self.addHost('h5', ip='10.0.2.1/24', mac='08:00:00:00:02:01')
        h6 = self.addHost('h6', ip='10.0.2.2/24', mac='08:00:00:00:02:02')
        h7 = self.addHost('h7', ip='10.0.2.3/24', mac='08:00:00:00:02:03')
        h8 = self.addHost('h8', ip='10.0.2.4/24', mac='08:00:00:00:02:04')

        # Spine-to-spine
        self.addLink(s1, s2, bw=1000, delay='1ms')

        # Spine-to-leaf (full mesh)
        self.addLink(s1, s3, bw=1000, delay='1ms')
        self.addLink(s1, s4, bw=1000, delay='1ms')
        self.addLink(s2, s3, bw=1000, delay='1ms')
        self.addLink(s2, s4, bw=1000, delay='1ms')

        # Leaf-to-leaf
        self.addLink(s3, s4, bw=1000, delay='1ms')

        # Leaf-to-host
        self.addLink(s3, h1, bw=100, delay='0.5ms')
        self.addLink(s3, h2, bw=100, delay='0.5ms')
        self.addLink(s3, h3, bw=100, delay='0.5ms')
        self.addLink(s3, h4, bw=100, delay='0.5ms')

        self.addLink(s4, h5, bw=100, delay='0.5ms')
        self.addLink(s4, h6, bw=100, delay='0.5ms')
        self.addLink(s4, h7, bw=100, delay='0.5ms')
        self.addLink(s4, h8, bw=100, delay='0.5ms')


# Switch metadata for MCP controller
SWITCH_CONFIG = {
    's1': {
        'device_id': 0,
        'grpc_port': 50051,
        'thrift_port': 9090,
        'role': 'spine',
        'centrality': 0.83,
    },
    's2': {
        'device_id': 1,
        'grpc_port': 50052,
        'thrift_port': 9091,
        'role': 'spine',
        'centrality': 0.83,
    },
    's3': {
        'device_id': 2,
        'grpc_port': 50053,
        'thrift_port': 9092,
        'role': 'leaf',
        'centrality': 0.50,
    },
    's4': {
        'device_id': 3,
        'grpc_port': 50054,
        'thrift_port': 9093,
        'role': 'leaf',
        'centrality': 0.50,
    },
}


def main():
    parser = argparse.ArgumentParser(
        description='MCP Mininet topology with BMv2 switches')
    parser.add_argument('--p4json', default=DEFAULT_P4JSON,
                        help='Path to compiled P4 JSON')
    args = parser.parse_args()

    if not os.path.exists(args.p4json):
        error(f'P4 JSON not found: {args.p4json}\n')
        error('Run "make build" first.\n')
        sys.exit(1)

    setLogLevel('info')
    topo = MCPTopo(json_path=args.p4json)
    net = Mininet(topo=topo, link=TCLink, controller=None)

    info('\n*** Starting network with BMv2 switches ***\n')
    net.start()

    # Set default routes on hosts
    for i in range(1, 5):
        net.get(f'h{i}').cmd('ip route add default via 10.0.1.254')
    for i in range(5, 9):
        net.get(f'h{i}').cmd('ip route add default via 10.0.2.254')

    info('\n*** Waiting for BMv2 switches to initialize...\n')
    time.sleep(2)

    info('\n*** Topology ready. Switch gRPC ports:\n')
    for name, cfg in SWITCH_CONFIG.items():
        info(f'    {name} ({cfg["role"]}): '
             f'gRPC={cfg["grpc_port"]}, '
             f'device_id={cfg["device_id"]}, '
             f'centrality={cfg["centrality"]}\n')

    info('\n*** Run MCP controller in another terminal:\n')
    info('    python3 controller/mcp_controller.py --verbose\n\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
