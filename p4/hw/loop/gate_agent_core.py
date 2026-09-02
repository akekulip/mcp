"""SDK-independent fail-closed helpers for the switch-side gate agent."""

import hashlib
import pathlib


ACT_ENTER = "Ingress.act_enter"
DEFAULT_MCP_PORTS = (9, 10, 164, 165, 166, 167, 172, 173, 174, 175)
PORT_STAT_DEV_PORT = "$DEV_PORT"
PORT_STAT_RX = "$FramesReceivedOK"
PORT_STAT_TX = "$FramesTransmittedOK"


def format_arm_reply(sublink, ranges):
    """Return injector detail followed by the protocol's standard OK terminator."""
    ranges = tuple(ranges)
    encoded = " ".join("%d %d" % bounds for bounds in ranges)
    return "ARMED %d %s\nOK %d\n" % (sublink, encoded, len(ranges))


def format_blackhole_reply(sublink, low, high):
    """Return full-range injector detail plus the standard OK terminator."""
    return "BLACKHOLED %d [%d..%d]\nOK 1\n" % (sublink, low, high)


def format_spread_reply(sublink, packet_count, drop_count, phase, ranges):
    """Return exact spread injector detail plus the standard OK terminator."""
    return "SPREAD %d %d %d %d\nOK %d\n" % (
        sublink, packet_count, drop_count, phase, len(tuple(ranges)))


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256_manifest(root, manifest_name, expected_files=None):
    """Verify a sha256sum manifest and return the manifest's own identity.

    Paths must be relative descendants of ``root``.  When ``expected_files`` is
    supplied, the manifest must name exactly that set, closing the import-closure
    gap where a current entry point silently imports an older unsealed helper.
    """
    root = pathlib.Path(root).resolve()
    manifest = (root / manifest_name).resolve()
    if manifest.parent != root or not manifest.is_file():
        raise RuntimeError("missing or unsafe manifest %s" % manifest_name)
    rows = {}
    for number, raw in enumerate(manifest.read_text().splitlines(), 1):
        fields = raw.split(None, 1)
        if len(fields) != 2 or len(fields[0]) != 64:
            raise RuntimeError("malformed manifest row %d" % number)
        digest, relative = fields[0].lower(), fields[1].strip()
        if any(char not in "0123456789abcdef" for char in digest):
            raise RuntimeError("malformed manifest digest on row %d" % number)
        if relative.startswith("*"):
            relative = relative[1:]
        path = pathlib.Path(relative)
        if path.is_absolute() or ".." in path.parts or relative in rows:
            raise RuntimeError("unsafe or duplicate manifest path %s" % relative)
        resolved = (root / path).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise RuntimeError("manifest path escapes runtime root") from error
        rows[relative] = (digest, resolved)
    if not rows:
        raise RuntimeError("empty manifest")
    if expected_files is not None and set(rows) != set(expected_files):
        raise RuntimeError("manifest file set does not match expected import closure")
    for relative, (expected, path) in rows.items():
        if not path.is_file():
            raise RuntimeError("manifest file missing: %s" % relative)
        actual = _sha256(path)
        if actual != expected:
            raise RuntimeError("sha256 mismatch for %s" % relative)
    return _sha256(manifest)


def verify_loaded_build(root, program, build_identity, proc_root="/proc"):
    """Prove the sealed build identity belongs to the live program owner."""
    root = pathlib.Path(root).resolve()
    receipt = root / (program + ".loaded-build.sha256")
    try:
        fields = receipt.read_text().split()
    except OSError as error:
        raise RuntimeError("missing loaded-build receipt") from error
    if len(fields) != 2 or not fields[0].isdigit():
        raise RuntimeError("malformed loaded-build receipt")
    pid, loaded_identity = int(fields[0]), fields[1]
    if loaded_identity != build_identity:
        raise RuntimeError("loaded build identity does not match sealed build")
    proc = pathlib.Path(proc_root) / str(pid)
    try:
        comm = (proc / "comm").read_text().strip()
        command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace")
    except OSError as error:
        raise RuntimeError("loaded-build owner is not live") from error
    expected_conf = str(root / (program + "_abs.conf"))
    if comm != "bf_switchd" or expected_conf not in command:
        raise RuntimeError("loaded-build receipt does not name the expected bf_switchd")
    return pid


def compute_switch_id(machine_id, hostname, device_id):
    normalized = "%s\n%s\n%d\n" % (machine_id.strip(), hostname.strip(), device_id)
    if not machine_id.strip() or not hostname.strip() or device_id < 0:
        raise RuntimeError("stable switch identity inputs are unavailable")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_loaded_setup(root, program, switch_identity, setup_identity, switchd_pid):
    """Prove the sealed setup identity was applied to the live switch owner."""
    receipt = pathlib.Path(root).resolve() / (program + ".loaded-setup.sha256")
    try:
        fields = receipt.read_text().split()
    except OSError as error:
        raise RuntimeError("missing loaded-setup receipt") from error
    if len(fields) != 3 or not fields[0].isdigit():
        raise RuntimeError("malformed loaded-setup receipt")
    receipt_pid, receipt_switch, receipt_identity = int(fields[0]), fields[1], fields[2]
    if receipt_pid != switchd_pid:
        raise RuntimeError("loaded setup does not name the live build owner")
    if receipt_switch != switch_identity:
        raise RuntimeError("loaded setup names another switch")
    if receipt_identity != setup_identity:
        raise RuntimeError("loaded setup identity does not match sealed setup")


def peer_allowed(peer_ip, allowed_peers):
    return peer_ip in allowed_peers


def is_not_found(error):
    return "NOT_FOUND" in str(error).upper()


def add_batch_strict(table, target, keys, data):
    """Issue exactly one batch call; any BFRT failure propagates to the client."""
    table.entry_add(target, keys, data)


def clear_entries_strict(table, target, keys):
    """Delete a snapshot completely; partial cleanup is an invalid reset."""
    failures = []
    for key in keys:
        try:
            table.entry_del(target, [key])
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise RuntimeError("failed to clear %d/%d entries: %s" %
                           (len(failures), len(keys), failures[0][:80]))
    return len(keys)


def sync_counters_strict(table, target):
    """Synchronize direct counters or propagate the BFRT failure to the caller."""
    table.operations_execute(target, "SyncCounters")


def parse_uint(fields, command, minimum, maximum):
    if len(fields) != 2 or fields[0] != command:
        raise ValueError("%s requires exactly one argument" % command)
    try:
        value = int(fields[1], 0)
    except ValueError as error:
        raise ValueError("%s argument must be an integer" % command) from error
    if not minimum <= value <= maximum:
        raise ValueError("%s argument outside %d..%d" % (command, minimum, maximum))
    return value


def parse_bank_command(fields):
    return parse_uint(fields, "N", 0, 1)


def parse_epoch_command(fields):
    return parse_uint(fields, "E", 0, 0xFFFF)


def parse_port_stats_command(fields):
    """Parse ``M [dev_port ...]`` as sorted unique decimal dev ports."""
    if not fields or fields[0] != "M":
        raise ValueError("M requires zero or more decimal dev ports")
    if len(fields) == 1:
        return DEFAULT_MCP_PORTS
    ports = []
    seen = set()
    for raw in fields[1:]:
        if not raw or any(char not in "0123456789" for char in raw):
            raise ValueError("M dev ports must be decimal integers")
        port = int(raw, 10)
        if not 0 <= port <= 511:
            raise ValueError("M dev port outside 0..511")
        if port in seen:
            raise ValueError("duplicate M dev port %d" % port)
        seen.add(port)
        ports.append(port)
    return tuple(sorted(ports))


def parse_blackhole_command(fields):
    """Parse either ``K sublink`` or ``K sublink low high`` exactly."""
    if len(fields) == 2:
        return parse_uint(fields, "K", 0, 1023), 0, 0xFFFF
    if len(fields) != 4 or fields[0] != "K":
        raise ValueError("K requires a sublink, optionally followed by low and high")
    try:
        sublink, low, high = (int(value, 0) for value in fields[1:])
    except ValueError as error:
        raise ValueError("K arguments must be integers") from error
    if not 0 <= sublink < 1024:
        raise ValueError("K sublink outside 0..1023")
    if not 0 <= low <= high <= 0xFFFF:
        raise ValueError("sequence range outside 0..65535")
    return sublink, low, high


def parse_spread_command(fields):
    """Parse ``S sublink packet_count drop_count phase`` exactly."""
    if len(fields) != 5 or fields[0] != "S":
        raise ValueError("S requires sublink, packet_count, drop_count, and phase")
    try:
        sublink, packet_count, drop_count, phase = (int(value, 0) for value in fields[1:])
    except ValueError as error:
        raise ValueError("S arguments must be integers") from error
    if not 0 <= sublink < 1024:
        raise ValueError("S sublink outside 0..1023")
    if not 1 <= packet_count <= 254:
        raise ValueError("S packet_count outside 1..254")
    if not 1 <= drop_count <= packet_count:
        raise ValueError("S drop_count outside 1..packet_count")
    if phase < 0:
        raise ValueError("S phase must be non-negative")
    return sublink, packet_count, drop_count, phase % packet_count


def _action_name(row):
    name = row.get("action_name")
    if not isinstance(name, str) or not name:
        raise RuntimeError("malformed action data: missing action_name")
    return name


def _is_act_enter(row):
    return _action_name(row).endswith("act_enter")


def _normalise_action_fields(row):
    """Return the act_enter arguments in schema order, preserving existing values."""
    fields = []
    for name in ("next_hop", "epoch", "bank"):
        if name in row:
            fields.append((name, row[name]))
    if not fields:
        raise RuntimeError("malformed action data: no act_enter fields")
    if "next_hop" not in row:
        raise RuntimeError("missing action field next_hop")
    return fields


def _read_act_enter_rows(table, target):
    rows = []
    for data, key in table.entry_get(target, None, {"from_hw": True}):
        row = data.to_dict()
        if _is_act_enter(row):
            rows.append((key, row))
    return rows


def _port_from_key(key):
    row = key.to_dict()
    value = row.get(PORT_STAT_DEV_PORT)
    if not isinstance(value, dict) or "value" not in value:
        raise RuntimeError("malformed port stat key")
    port = value["value"]
    if isinstance(port, bool) or not isinstance(port, int):
        raise RuntimeError("malformed port stat key")
    return port


def _port_counter(row, name):
    if name not in row:
        raise RuntimeError("missing port counter %s" % name)
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError("malformed port counter %s" % name)
    return value


def read_port_stats_rows(table, target, dev_ports, key_tuple):
    """Read selected $PORT_STAT rows and return ``(port, rx_ok, tx_ok)`` tuples."""
    requested = tuple(sorted(dev_ports))
    keys = [table.make_key([key_tuple(PORT_STAT_DEV_PORT, dev_port)])
            for dev_port in requested]
    rows = {}
    for data, key in table.entry_get(target, keys, {"from_hw": True}):
        port = _port_from_key(key)
        if port not in requested:
            raise RuntimeError("unexpected port stat row %d" % port)
        values = data.to_dict()
        rows[port] = (
            _port_counter(values, PORT_STAT_RX),
            _port_counter(values, PORT_STAT_TX),
        )
    missing = [port for port in requested if port not in rows]
    if missing:
        raise RuntimeError("missing port stats rows: %s" % missing[:8])
    return tuple((port, rows[port][0], rows[port][1]) for port in requested)


def format_port_stats_reply(rows):
    ordered = tuple(sorted(rows))
    payload = "".join("M %d %d %d\n" % row for row in ordered)
    return payload + "OK %d\n" % len(ordered)


def rewrite_act_enter_field(table, target, data_tuple, field_name, value, expected_count=None):
    """Rewrite one tbl_final act_enter field, preserving all other action args.

    This helper is deliberately SDK-independent: callers provide the BFRT table,
    target, and DataTuple constructor.  It fails closed on schema mismatch, zero
    matches, partial writes, and readback mismatches.
    """
    rows = _read_act_enter_rows(table, target)
    if not rows:
        raise RuntimeError("no act_enter rows found")
    if expected_count is not None and len(rows) != expected_count:
        raise RuntimeError("expected %d act_enter rows, found %d" %
                           (expected_count, len(rows)))

    keys = []
    updates = []
    for key, row in rows:
        if field_name not in row:
            raise RuntimeError("missing action field %s" % field_name)
        fields = [(name, value if name == field_name else existing)
                  for name, existing in _normalise_action_fields(row)]
        keys.append(key)
        updates.append(table.make_data([data_tuple(name, field_value)
                                        for name, field_value in fields], ACT_ENTER))

    # Validate every row before issuing one BFRT batch.  A malformed later row must
    # never leave the earlier rows carrying a new bank/epoch while its peers carry
    # the old one.
    table.entry_mod(target, keys, updates)

    after = _read_act_enter_rows(table, target)
    if len(after) != len(rows):
        raise RuntimeError("act_enter row count changed from %d to %d during readback" %
                           (len(rows), len(after)))
    mismatches = [key for key, row in after if row.get(field_name) != value]
    if mismatches:
        raise RuntimeError("readback mismatch for %d act_enter rows" % len(mismatches))
    if expected_count is not None and len(after) != expected_count:
        raise RuntimeError("expected %d act_enter rows after write, found %d" %
                           (expected_count, len(after)))
    return len(rows)
