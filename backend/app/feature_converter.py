
from __future__ import annotations

from typing import Any

from backend.app.flow_extractor import (
    NetworkFlow,
    active_idle_statistics,
    inter_arrival_statistics,
    packet_length_statistics,
)


MODEL_FEATURES = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)


class FeatureConversionError(ValueError):
    """Raised when a complete model feature vector cannot be produced."""

    def __init__(
        self,
        message: str,
        unsupported_features: list[str] | None = None,
    ):
        super().__init__(message)
        self.unsupported_features = unsupported_features or []


def _safe_rate(numerator: float, duration_seconds: float) -> float:
    if duration_seconds <= 0:
        return 0.0
    return numerator / duration_seconds


def _packet_stats(lengths: list[int]) -> dict[str, float]:
    return packet_length_statistics(lengths)


def _iat_stats(timestamps: list[float]) -> dict[str, float]:
    return inter_arrival_statistics(timestamps)


def _average_per_group(total: float, groups: float) -> float:
    """Return the average for observed groups, or zero if none exist."""
    return total / groups if groups > 0 else 0.0


def get_supported_features(flow: NetworkFlow) -> dict[str, float]:
    """Calculate available features from an extracted network flow.

    Bulk and subflow metrics use the project's provisional definitions.
    Validate them against the training feature-generation pipeline before
    treating these values as CICFlowMeter-equivalent.
    """
    forward = flow.forward_packet_lengths
    backward = flow.backward_packet_lengths
    all_lengths = flow.packet_lengths

    fwd_stats = _packet_stats(forward)
    bwd_stats = _packet_stats(backward)
    packet_stats = _packet_stats(all_lengths)

    flow_iat = _iat_stats(flow.packet_timestamps)
    fwd_iat = _iat_stats(flow.forward_packet_timestamps)
    bwd_iat = _iat_stats(flow.backward_packet_timestamps)

    active_idle = active_idle_statistics(flow.packet_timestamps)
    duration = flow.duration_seconds

    fwd_count = len(forward)
    bwd_count = len(backward)
    total_count = fwd_count + bwd_count

    fwd_bytes = float(sum(forward))
    bwd_bytes = float(sum(backward))
    total_bytes = fwd_bytes + bwd_bytes

    fwd_flags = flow.forward_tcp_flags
    bwd_flags = flow.backward_tcp_flags
    all_flags = fwd_flags + bwd_flags

    fwd_bulk = flow.forward_bulk_statistics
    bwd_bulk = flow.backward_bulk_statistics
    fwd_subflow = flow.forward_subflow_statistics
    bwd_subflow = flow.backward_subflow_statistics

    features: dict[str, float] = {
        "Destination Port": float(flow.destination_port),
        "Flow Duration": flow.duration_microseconds,
        "Total Fwd Packets": float(fwd_count),
        "Total Backward Packets": float(bwd_count),
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Max": fwd_stats["max"],
        "Fwd Packet Length Min": fwd_stats["min"],
        "Fwd Packet Length Mean": fwd_stats["mean"],
        "Fwd Packet Length Std": fwd_stats["std"],
        "Bwd Packet Length Max": bwd_stats["max"],
        "Bwd Packet Length Min": bwd_stats["min"],
        "Bwd Packet Length Mean": bwd_stats["mean"],
        "Bwd Packet Length Std": bwd_stats["std"],
        "Flow Bytes/s": _safe_rate(total_bytes, duration),
        "Flow Packets/s": _safe_rate(float(total_count), duration),
        "Flow IAT Mean": flow_iat["mean"],
        "Flow IAT Std": flow_iat["std"],
        "Flow IAT Max": flow_iat["max"],
        "Flow IAT Min": flow_iat["min"],
        "Fwd IAT Total": (
            (
                max(flow.forward_packet_timestamps)
                - min(flow.forward_packet_timestamps)
            )
            * 1_000_000
            if fwd_count > 1
            else 0.0
        ),
        "Fwd IAT Mean": fwd_iat["mean"],
        "Fwd IAT Std": fwd_iat["std"],
        "Fwd IAT Max": fwd_iat["max"],
        "Fwd IAT Min": fwd_iat["min"],
        "Bwd IAT Total": (
            (
                max(flow.backward_packet_timestamps)
                - min(flow.backward_packet_timestamps)
            )
            * 1_000_000
            if bwd_count > 1
            else 0.0
        ),
        "Bwd IAT Mean": bwd_iat["mean"],
        "Bwd IAT Std": bwd_iat["std"],
        "Bwd IAT Max": bwd_iat["max"],
        "Bwd IAT Min": bwd_iat["min"],
        "Fwd PSH Flags": float(sum(bool(flag & 8) for flag in fwd_flags)),
        "Bwd PSH Flags": float(sum(bool(flag & 8) for flag in bwd_flags)),
        "Fwd URG Flags": float(sum(bool(flag & 32) for flag in fwd_flags)),
        "Bwd URG Flags": float(sum(bool(flag & 32) for flag in bwd_flags)),
        "Fwd Header Length": float(sum(flow.forward_tcp_header_lengths)),
        "Bwd Header Length": float(sum(flow.backward_tcp_header_lengths)),
        "Fwd Packets/s": _safe_rate(float(fwd_count), duration),
        "Bwd Packets/s": _safe_rate(float(bwd_count), duration),
        "Min Packet Length": packet_stats["min"],
        "Max Packet Length": packet_stats["max"],
        "Packet Length Mean": packet_stats["mean"],
        "Packet Length Std": packet_stats["std"],
        "Packet Length Variance": packet_stats["variance"],
        "FIN Flag Count": float(sum(bool(flag & 1) for flag in all_flags)),
        "SYN Flag Count": float(sum(bool(flag & 2) for flag in all_flags)),
        "RST Flag Count": float(sum(bool(flag & 4) for flag in all_flags)),
        "PSH Flag Count": float(sum(bool(flag & 8) for flag in all_flags)),
        "ACK Flag Count": float(sum(bool(flag & 16) for flag in all_flags)),
        "URG Flag Count": float(sum(bool(flag & 32) for flag in all_flags)),
        "CWE Flag Count": float(sum(bool(flag & 128) for flag in all_flags)),
        "ECE Flag Count": float(sum(bool(flag & 64) for flag in all_flags)),
        "Down/Up Ratio": float(bwd_count) / fwd_count if fwd_count else 0.0,
        "Average Packet Size": (
            total_bytes / total_count if total_count else 0.0
        ),
        "Avg Fwd Segment Size": fwd_stats["mean"],
        "Avg Bwd Segment Size": bwd_stats["mean"],
        "Fwd Header Length.1": float(sum(flow.forward_tcp_header_lengths)),
        "Fwd Avg Bytes/Bulk": _average_per_group(
            fwd_bulk["bytes"], fwd_bulk["groups"]
        ),
        "Fwd Avg Packets/Bulk": _average_per_group(
            fwd_bulk["packets"], fwd_bulk["groups"]
        ),
        "Fwd Avg Bulk Rate": fwd_bulk["rate"],
        "Bwd Avg Bytes/Bulk": _average_per_group(
            bwd_bulk["bytes"], bwd_bulk["groups"]
        ),
        "Bwd Avg Packets/Bulk": _average_per_group(
            bwd_bulk["packets"], bwd_bulk["groups"]
        ),
        "Bwd Avg Bulk Rate": bwd_bulk["rate"],
        "Subflow Fwd Packets": _average_per_group(
            float(fwd_count), fwd_subflow["groups"]
        ),
        "Subflow Fwd Bytes": _average_per_group(
            fwd_bytes, fwd_subflow["groups"]
        ),
        "Subflow Bwd Packets": _average_per_group(
            float(bwd_count), bwd_subflow["groups"]
        ),
        "Subflow Bwd Bytes": _average_per_group(
            bwd_bytes, bwd_subflow["groups"]
        ),
        **active_idle,
    }

    # First observed TCP windows are not guaranteed to be the true initial
    # windows if capture begins after a connection has already started.
    if flow.forward_tcp_windows:
        features["Init_Win_bytes_forward"] = float(
            flow.forward_tcp_windows[0]
        )

    if flow.backward_tcp_windows:
        features["Init_Win_bytes_backward"] = float(
            flow.backward_tcp_windows[0]
        )

    features["act_data_pkt_fwd"] = float(
        sum(length > 0 for length in flow.forward_tcp_payload_lengths)
    )

    # Provisional approximation: validate against the original training
    # feature-generation pipeline before relying on this value.
    if flow.forward_tcp_header_lengths:
        features["min_seg_size_forward"] = float(
            min(flow.forward_tcp_header_lengths)
        )

    return features


def get_supported_feature_names() -> list[str]:
    """Return the feature names calculated by get_supported_features."""
    return list(get_supported_features.__annotations__) if False else [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length.1",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]


def convert_flow_to_model_features(flow: NetworkFlow) -> dict[str, float]:
    """Return a complete feature vector only when all features are available."""
    supported = get_supported_features(flow)
    missing = [name for name in MODEL_FEATURES if name not in supported]

    if missing:
        raise FeatureConversionError(
            "Cannot safely create the complete model vector: "
            f"{len(missing)} features are not yet supported.",
            unsupported_features=missing,
        )

    return {name: supported[name] for name in MODEL_FEATURES}


def feature_support_report() -> dict[str, Any]:
    supported_names = set(get_supported_feature_names())
    unsupported = [
        name for name in MODEL_FEATURES if name not in supported_names
    ]

    return {
        "total_features": len(MODEL_FEATURES),
        "supported_count": len(supported_names),
        "unsupported_count": len(unsupported),
        "supported_features": [
            name for name in MODEL_FEATURES if name in supported_names
        ],
        "unsupported_features": unsupported,
    }
