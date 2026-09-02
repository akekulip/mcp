"""Pure helpers shared by the live Tofino fault-injector agent and its tests."""


def _compress_non_wrapping_ranges(values):
    values = tuple(sorted(values))
    if not values:
        return ()
    ranges = []
    low = high = values[0]
    for value in values[1:]:
        if value == high + 1:
            high = value
        else:
            ranges.append((low, high))
            low = high = value
    ranges.append((low, high))
    return tuple(ranges)


def _require_exact_int(value, field):
    if type(value) is not int:
        raise ValueError("%s must be an exact integer" % field)
    return value


def modular_drop_ranges(current_sequence, drop_count):
    """Return inclusive 16-bit ranges after two deliberately safe packets.

    Tofino range keys do not wrap.  A modular interval that crosses 0 must
    therefore be represented by two disjoint entries; otherwise long campaigns
    intermittently arm an invalid or incomplete fault.
    """
    current_sequence = _require_exact_int(current_sequence, "current_sequence")
    drop_count = _require_exact_int(drop_count, "drop_count")
    if not 0 <= current_sequence <= 0xFFFF:
        raise ValueError("current sequence must fit 16 bits")
    if not 1 <= drop_count <= 0x10000:
        raise ValueError("drop count must be in 1..65536")
    if drop_count == 0x10000:
        return ((0, 0xFFFF),)
    low = (current_sequence + 3) & 0xFFFF
    high = (current_sequence + 2 + drop_count) & 0xFFFF
    if low <= high:
        return ((low, high),)
    return ((low, 0xFFFF), (0, high))


def modular_spread_drop_ranges(current_sequence, packet_count, drop_count, phase=0):
    """Return exact dispersed inclusive ranges within the next packet horizon."""
    current_sequence = _require_exact_int(current_sequence, "current_sequence")
    packet_count = _require_exact_int(packet_count, "packet_count")
    drop_count = _require_exact_int(drop_count, "drop_count")
    phase = _require_exact_int(phase, "phase")
    if not 0 <= current_sequence <= 0xFFFF:
        raise ValueError("current sequence must fit 16 bits")
    if not 1 <= drop_count <= packet_count <= 254:
        raise ValueError("require 1 <= drop_count <= packet_count <= 254")
    if phase < 0:
        raise ValueError("phase must be non-negative")
    phase %= packet_count
    offsets = {
        (phase + (i * packet_count) // drop_count) % packet_count
        for i in range(drop_count)
    }
    if len(offsets) != drop_count:
        raise RuntimeError("spread schedule did not produce exact unique drops")
    values = [((current_sequence + offset) & 0xFFFF) for offset in offsets]
    return _compress_non_wrapping_ranges(values)
