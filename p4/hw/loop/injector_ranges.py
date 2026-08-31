"""Pure helpers shared by the live Tofino fault-injector agent and its tests."""


def modular_drop_ranges(current_sequence, drop_count):
    """Return inclusive 16-bit ranges after two deliberately safe packets.

    Tofino range keys do not wrap.  A modular interval that crosses 0 must
    therefore be represented by two disjoint entries; otherwise long campaigns
    intermittently arm an invalid or incomplete fault.
    """
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
