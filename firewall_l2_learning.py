#!/usr/bin/env python

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid, str_to_bool
from pox.lib.addresses import EthAddr, IPAddr
import time

log = core.getLogger()

# Configurable flood delay
_flood_delay = 0

class IntegratedSwitch (object):
    """
    Integrated OpenFlow Switch with L2 Learning and Firewall Capabilities
    """
    def __init__ (self, connection, transparent, firewall_config):
        # Switch connection
        self.connection = connection
        self.transparent = transparent

        # MAC to Port mapping for L2 learning
        self.macToPort = {}

        # Firewall configuration
        self.blocked_ips = set(firewall_config.get('blocked_ips', []))
        self.blocked_macs = set(firewall_config.get('blocked_macs', []))
        self.blocked_ports = set(firewall_config.get('blocked_ports', []))

        # Tracking blocked packets to prevent log spam
        self.blocked_packet_count = {}
        self.last_log_time = {}

        # Add listeners for packet-in events
        connection.addListeners(self)

        # Flood delay management
        self.hold_down_expired = _flood_delay == 0

        # Log initialization details
        log.info("Integrated Switch initialized on switch %s", dpid_to_str(connection.dpid))
        log.info("Blocked IPs: %s", self.blocked_ips)
        log.info("Blocked MACs: %s", self.blocked_macs)
        log.info("Blocked Ports: %s", self.blocked_ports)

    def _handle_PacketIn (self, event):
        """
        Handle incoming packets with combined L2 learning and firewall logic
        """
        packet = event.parsed

        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                if self.hold_down_expired is False:
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding",
                        dpid_to_str(event.dpid))

                if message is not None:
                    log.debug(message)

                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                pass

            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop (duration = None):
            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        # Prevent log spam by tracking blocked packets
        def log_blocked_packet(block_type, block_detail):
            # Use a tuple of block type and detail as the key
            key = (block_type, block_detail)
            current_time = time.time()

            # Only log once every 5 seconds for each unique blocked packet
            if (key not in self.last_log_time or
                current_time - self.last_log_time[key] > 5):

                if key not in self.blocked_packet_count:
                    self.blocked_packet_count[key] = 1
                else:
                    self.blocked_packet_count[key] += 1

                log.warning("Blocked %s: %s (count: %d)",
                            block_type, block_detail,
                            self.blocked_packet_count[key])

                # Update last log time
                self.last_log_time[key] = current_time

        # FIREWALL CHECKS
        # Check for blocked MAC addresses (source and destination)
        blocked_mac_match = False
        blocked_macs = []
        if packet.src in self.blocked_macs:
            blocked_macs.append(str(packet.src))
            blocked_mac_match = True
        if packet.dst in self.blocked_macs:
            blocked_macs.append(str(packet.dst))
            blocked_mac_match = True

        if blocked_mac_match:
            log_blocked_packet("MAC", ", ".join(blocked_macs))
            drop()
            return

        # Check for blocked IP addresses (if available)
        try:
            ip_packet = packet.find('ipv4')
            if ip_packet:
                blocked_ips = []
                if ip_packet.srcip in self.blocked_ips:
                    blocked_ips.append(str(ip_packet.srcip))
                if ip_packet.dstip in self.blocked_ips:
                    blocked_ips.append(str(ip_packet.dstip))

                if blocked_ips:
                    log_blocked_packet("IP", ", ".join(blocked_ips))
                    drop()
                    return
        except Exception as e:
            log.error("Error processing IP packet: %s", str(e))

        # Check for blocked ports
        try:
            tcp_packet = packet.find('tcp')
            if tcp_packet:
                blocked_ports = []
                if tcp_packet.srcport in self.blocked_ports:
                    blocked_ports.append(str(tcp_packet.srcport))
                if tcp_packet.dstport in self.blocked_ports:
                    blocked_ports.append(str(tcp_packet.dstport))

                if blocked_ports:
                    log_blocked_packet("Port", ", ".join(blocked_ports))
                    drop()
                    return
        except Exception as e:
            log.error("Error processing TCP packet: %s", str(e))

        # L2 LEARNING SWITCH LOGIC
        # Update MAC to port mapping
        self.macToPort[packet.src] = event.port

        # Transparent mode handling
        if not self.transparent:
            # Safely handle LLDP and bridge filtering
            try:
                if packet.type == packet.LLDP_TYPE:
                    drop()
                    return
            except Exception as e:
                log.error("Error processing LLDP packet: %s", str(e))

        # Multicast handling
        if packet.dst.is_multicast:
            flood()
        else:
            # Destination MAC not in mapping
            if packet.dst not in self.macToPort:
                flood("Port for %s unknown -- flooding" % (packet.dst,))
            else:
                port = self.macToPort[packet.dst]

                # Prevent packet to same input port
                if port == event.port:
                    log.warning("Same port for packet from %s -> %s on %s.%s. Drop."
                        % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return

                # Install flow and forward
                log.debug("Installing flow for %s.%i -> %s.%i" %
                          (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port = port))
                msg.data = event.ofp
                self.connection.send(msg)


class IntegratedController (object):
    """
    Manages integrated switches for each connection
    """
    def __init__ (self, transparent, firewall_config, ignore = None):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.firewall_config = firewall_config
        self.ignore = set(ignore) if ignore else ()

    def _handle_ConnectionUp (self, event):
        if event.dpid in self.ignore:
            log.debug("Ignoring connection %s" % (event.connection,))
            return
        log.debug("Connection %s" % (event.connection,))
        IntegratedSwitch(event.connection, self.transparent, self.firewall_config)


def launch (transparent=False, hold_down=0,
            blocked_ips='', blocked_macs='', blocked_ports='',
            ignore = None):
    """
    Launch the integrated SDN controller
    """
    global _flood_delay
    try:
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    # Parse blocked IPs
    if blocked_ips:
        blocked_ips = [IPAddr(ip.strip()) for ip in blocked_ips.split(',') if ip.strip()]
    else:
        blocked_ips = []

    # Parse blocked MACs
    if blocked_macs:
        blocked_macs = [EthAddr(mac.strip()) for mac in blocked_macs.split(',') if mac.strip()]
    else:
        blocked_macs = []

    # Parse blocked ports
    if blocked_ports:
        blocked_ports = [int(port.strip()) for port in blocked_ports.split(',') if port.strip()]
    else:
        blocked_ports = []

    # Firewall configuration dictionary
    firewall_config = {
        'blocked_ips': blocked_ips,
        'blocked_macs': blocked_macs,
        'blocked_ports': blocked_ports
    }

    # Handle ignored switches
    if ignore:
        ignore = ignore.replace(',', ' ').split()
        ignore = set(str_to_dpid(dpid) for dpid in ignore)

    # Register the integrated controller
    core.registerNew(IntegratedController,
                     str_to_bool(transparent),
                     firewall_config,
                     ignore)