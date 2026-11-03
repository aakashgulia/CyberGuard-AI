from backend.app.flow_extractor import (
    PacketRecord,
    calculate_bulk_statistics,
    calculate_subflow_statistics,
)


def make_record(
    timestamp: float,
    direction: str = "forward",
    packet_length: int = 100,
    payload_length: int = 80,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        direction=direction,
        packet_length=packet_length,
        payload_length=payload_length,
    )


def test_bulk_statistics_counts_qualifying_group():
    records = [
        make_record(0.0),
        make_record(0.1),
        make_record(0.2),
        make_record(0.3),
    ]

    result = calculate_bulk_statistics(records, "forward")

    assert result["packets"] == 4.0
    assert result["bytes"] == 320.0
    assert result["groups"] == 1.0
    assert result["rate"] > 0.0


def test_bulk_statistics_ignores_groups_below_minimum():
    records = [
        make_record(0.0),
        make_record(0.1),
        make_record(0.2),
    ]

    result = calculate_bulk_statistics(records, "forward")

    assert result == {
        "packets": 0.0,
        "bytes": 0.0,
        "rate": 0.0,
        "groups": 0.0,
    }


def test_bulk_statistics_splits_groups_after_timeout():
    records = [
        make_record(0.0),
        make_record(0.1),
        make_record(0.2),
        make_record(0.3),
        make_record(2.0),
        make_record(2.1),
        make_record(2.2),
        make_record(2.3),
    ]

    result = calculate_bulk_statistics(records, "forward")

    assert result["packets"] == 8.0
    assert result["bytes"] == 640.0
    assert result["groups"] == 2.0


def test_bulk_statistics_ignores_other_direction():
    records = [
        make_record(i * 0.1, direction="backward")
        for i in range(4)
    ]

    result = calculate_bulk_statistics(records, "forward")

    assert result["groups"] == 0.0
    assert result["packets"] == 0.0
    assert result["bytes"] == 0.0


def test_subflow_statistics_splits_after_timeout():
    records = [
        make_record(0.0),
        make_record(0.1),
        make_record(2.0),
        make_record(2.1),
    ]

    result = calculate_subflow_statistics(records, "forward")

    assert result["packets"] == 4.0
    assert result["bytes"] == 400.0
    assert result["groups"] == 2.0


def test_subflow_statistics_returns_zero_for_empty_direction():
    records = [make_record(0.0, direction="backward")]

    result = calculate_subflow_statistics(records, "forward")

    assert result == {
        "packets": 0.0,
        "bytes": 0.0,
        "groups": 0.0,
    }
