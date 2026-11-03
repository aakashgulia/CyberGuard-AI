
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Any

FLOW_IDLE_TIMEOUT_SECONDS = 5.0
BULK_TIMEOUT_SECONDS = 1.0
SUBFLOW_TIMEOUT_SECONDS = 1.0
BULK_MIN_PACKETS = 4


def packet_length_statistics(
    lengths: list[int | float],
) -> dict[str, float]:
    if not lengths:
        return {
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "variance": 0.0,
        }

    values = [float(value) for value in lengths]
    average = mean(values)
    standard_deviation = pstdev(values)

    return {
        "min": min(values),
        "max": max(values),
        "mean": average,
        "std": standard_deviation,
        "variance": standard_deviation**2,
    }


def inter_arrival_statistics(
    timestamps: list[float],
) -> dict[str, float]:
    ordered = sorted(float(timestamp) for timestamp in timestamps)
    intervals = [
        (ordered[index] - ordered[index - 1]) * 1_000_000
        for index in range(1, len(ordered))
    ]

    if not intervals:
        return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}

    stats = packet_length_statistics(intervals)
    return {
        "mean": stats["mean"],
        "std": stats["std"],
        "max": stats["max"],
        "min": stats["min"],
    }


def active_idle_statistics(
    timestamps: list[float],
    idle_timeout_seconds: float = FLOW_IDLE_TIMEOUT_SECONDS,
) -> dict[str, float]:
    if idle_timeout_seconds <= 0:
        raise ValueError("idle_timeout_seconds must be positive")

    ordered = sorted(float(timestamp) for timestamp in timestamps)

    if len(ordered) < 2:
        return {
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

    active_durations: list[float] = []
    idle_durations: list[float] = []
    active_start = ordered[0]
    previous = ordered[0]

    for timestamp in ordered[1:]:
        gap = timestamp - previous

        if gap > idle_timeout_seconds:
            active_durations.append(
                max(0.0, previous - active_start) * 1_000_000
            )
            idle_durations.append(gap * 1_000_000)
            active_start = timestamp

        previous = timestamp

    active_durations.append(
        max(0.0, ordered[-1] - active_start) * 1_000_000
    )

    active_stats = packet_length_statistics(active_durations)
    idle_stats = packet_length_statistics(idle_durations)

    return {
        "Active Mean": active_stats["mean"],
        "Active Std": active_stats["std"],
        "Active Max": active_stats["max"],
        "Active Min": active_stats["min"],
        "Idle Mean": idle_stats["mean"],
        "Idle Std": idle_stats["std"],
        "Idle Max": idle_stats["max"],
        "Idle Min": idle_stats["min"],
    }


@dataclass
class PacketRecord:
    timestamp: float
    direction: str
    packet_length: int
    payload_length: int
    tcp_flags: int | None = None


def calculate_bulk_statistics(
    records: list[PacketRecord],
    direction: str,
    timeout_seconds: float = BULK_TIMEOUT_SECONDS,
    minimum_packets: int = BULK_MIN_PACKETS,
) -> dict[str, float]:
    """Estimate directional payload bulk statistics.

    A candidate bulk consists of payload-bearing packets in the same
    direction, with no inter-packet gap greater than the configured
    timeout. Only groups meeting minimum_packets are counted.

    This is a project approximation, not a claim of CICFlowMeter parity.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if minimum_packets < 1:
        raise ValueError("minimum_packets must be positive")

    selected = sorted(
        (
            record
            for record in records
            if record.direction == direction and record.payload_length > 0
        ),
        key=lambda record: record.timestamp,
    )

    groups: list[list[PacketRecord]] = []
    current_group: list[PacketRecord] = []

    for record in selected:
        if (
            current_group
            and record.timestamp - current_group[-1].timestamp
            > timeout_seconds
        ):
            if len(current_group) >= minimum_packets:
                groups.append(current_group)
            current_group = []

        current_group.append(record)

    if len(current_group) >= minimum_packets:
        groups.append(current_group)

    bulk_packets = sum(len(group) for group in groups)
    bulk_bytes = sum(
        record.payload_length for group in groups for record in group
    )

    first_times = [
        group[0].timestamp for group in groups if len(group) >= minimum_packets
    ]
    last_times = [
        group[-1].timestamp for group in groups if len(group) >= minimum_packets
    ]

    elapsed = (
        max(last_times) - min(first_times)
        if first_times and last_times
        else 0.0
    )

    return {
        "packets": float(bulk_packets),
        "bytes": float(bulk_bytes),
        "rate": bulk_bytes / elapsed if elapsed > 0 else 0.0,
        "groups": float(len(groups)),
    }


def calculate_subflow_statistics(
    records: list[PacketRecord],
    direction: str,
    timeout_seconds: float = SUBFLOW_TIMEOUT_SECONDS,
) -> dict[str, float]:
    """Estimate directional subflow counts and bytes using time gaps.

    A new subflow starts when the gap between consecutive observed packets
    exceeds timeout_seconds. This segmentation requires validation against
    the exact dataset-generation implementation.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    selected = sorted(
        (record for record in records if record.direction == direction),
        key=lambda record: record.timestamp,
    )

    if not selected:
        return {"packets": 0.0, "bytes": 0.0, "groups": 0.0}

    groups = 1
    previous_timestamp = selected[0].timestamp

    for record in selected[1:]:
        if record.timestamp - previous_timestamp > timeout_seconds:
            groups += 1
        previous_timestamp = record.timestamp

    return {
        "packets": float(len(selected)),
        "bytes": float(sum(record.packet_length for record in selected)),
        "groups": float(groups),
    }


@dataclass
class NetworkFlow:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str

    packet_count: int = 0
    total_packet_bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    packet_lengths: list[int] = field(default_factory=list)
    packet_timestamps: list[float] = field(default_factory=list)

    forward_packet_lengths: list[int] = field(default_factory=list)
    backward_packet_lengths: list[int] = field(default_factory=list)
    forward_packet_timestamps: list[float] = field(default_factory=list)
    backward_packet_timestamps: list[float] = field(default_factory=list)

    forward_tcp_flags: list[int] = field(default_factory=list)
    backward_tcp_flags: list[int] = field(default_factory=list)
    forward_tcp_header_lengths: list[int] = field(default_factory=list)
    backward_tcp_header_lengths: list[int] = field(default_factory=list)
    forward_tcp_windows: list[int] = field(default_factory=list)
    backward_tcp_windows: list[int] = field(default_factory=list)
    forward_tcp_payload_lengths: list[int] = field(default_factory=list)
    backward_tcp_payload_lengths: list[int] = field(default_factory=list)

    packet_records: list[PacketRecord] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def duration_microseconds(self) -> float:
        return self.duration_seconds * 1_000_000

    @property
    def flow_inter_arrival_statistics(self) -> dict[str, float]:
        return inter_arrival_statistics(self.packet_timestamps)

    @property
    def forward_inter_arrival_statistics(self) -> dict[str, float]:
        return inter_arrival_statistics(self.forward_packet_timestamps)

    @property
    def backward_inter_arrival_statistics(self) -> dict[str, float]:
        return inter_arrival_statistics(self.backward_packet_timestamps)

    @property
    def active_idle_statistics(self) -> dict[str, float]:
        return active_idle_statistics(self.packet_timestamps)

    @property
    def forward_bulk_statistics(self) -> dict[str, float]:
        return calculate_bulk_statistics(self.packet_records, "forward")

    @property
    def backward_bulk_statistics(self) -> dict[str, float]:
        return calculate_bulk_statistics(self.packet_records, "backward")

    @property
    def forward_subflow_statistics(self) -> dict[str, float]:
        return calculate_subflow_statistics(self.packet_records, "forward")

    @property
    def backward_subflow_statistics(self) -> dict[str, float]:
        return calculate_subflow_statistics(self.packet_records, "backward")


def _get_packet_details(packet: Any) -> tuple | None:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    else:
        return None

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    if packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "TCP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
        tcp_flags = int(transport.flags)
        tcp_header_length = (
            int(transport.dataofs) * 4
            if transport.dataofs is not None
            else 20
        )
        tcp_window = int(transport.window)
        tcp_payload_length = len(bytes(transport.payload))
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "UDP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
        tcp_flags = None
        tcp_header_length = None
        tcp_window = None
        tcp_payload_length = len(bytes(transport.payload))
    else:
        return None

    packet_length = len(bytes(ip_layer))

    return (
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        tcp_flags,
        tcp_header_length,
        tcp_window,
        packet_length,
        tcp_payload_length,
    )


def extract_flows(packets: list[Any]) -> dict[tuple, NetworkFlow]:
    flows: dict[tuple, NetworkFlow] = {}

    for packet in packets:
        details = _get_packet_details(packet)
        if details is None:
            continue

        (
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            tcp_flags,
            tcp_header_length,
            tcp_window,
            packet_length,
            tcp_payload_length,
        ) = details

        forward_endpoint = (source_ip, source_port)
        backward_endpoint = (destination_ip, destination_port)
        endpoint_a, endpoint_b = sorted(
            (forward_endpoint, backward_endpoint)
        )
        key = (protocol, endpoint_a, endpoint_b)
        timestamp = float(packet.time)

        if key not in flows:
            flows[key] = NetworkFlow(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
            )

        flow = flows[key]
        flow.packet_count += 1
        flow.total_packet_bytes += packet_length
        flow.packet_lengths.append(packet_length)
        flow.packet_timestamps.append(timestamp)

        if flow.first_seen is None or timestamp < flow.first_seen:
            flow.first_seen = timestamp
        if flow.last_seen is None or timestamp > flow.last_seen:
            flow.last_seen = timestamp

        # Direction is relative to the first observed packet.
        is_forward = (
            source_ip == flow.source_ip
            and destination_ip == flow.destination_ip
            and source_port == flow.source_port
            and destination_port == flow.destination_port
        )
        direction = "forward" if is_forward else "backward"

        flow.packet_records.append(
            PacketRecord(
                timestamp=timestamp,
                direction=direction,
                packet_length=packet_length,
                payload_length=tcp_payload_length,
                tcp_flags=tcp_flags,
            )
        )

        if is_forward:
            flow.forward_packet_lengths.append(packet_length)
            flow.forward_packet_timestamps.append(timestamp)
        else:
            flow.backward_packet_lengths.append(packet_length)
            flow.backward_packet_timestamps.append(timestamp)

        if tcp_flags is not None:
            if is_forward:
                flow.forward_tcp_flags.append(tcp_flags)
                flow.forward_tcp_header_lengths.append(tcp_header_length)
                flow.forward_tcp_windows.append(tcp_window)
                flow.forward_tcp_payload_lengths.append(tcp_payload_length)
            else:
                flow.backward_tcp_flags.append(tcp_flags)
                flow.backward_tcp_header_lengths.append(tcp_header_length)
                flow.backward_tcp_windows.append(tcp_window)
                flow.backward_tcp_payload_lengths.append(tcp_payload_length)

    return flows
