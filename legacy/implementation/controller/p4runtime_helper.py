#!/usr/bin/env python3
"""
p4runtime_helper.py — P4Runtime client for BMv2

Enhanced with:
  - Bulk register reads (wildcard index)
  - Sketch reset (zero all register cells in batches)
  - Batched table writes for atomic deployment
  - SetForwardingPipelineConfig support
"""

import os
import grpc
from google.protobuf import text_format

try:
    from p4.v1 import p4runtime_pb2
    from p4.v1 import p4runtime_pb2_grpc
    from p4.config.v1 import p4info_pb2
except ImportError:
    print("ERROR: p4runtime protobuf stubs not found.")
    print("Install with: pip install p4runtime")
    raise


class P4RuntimeHelper:
    """Connects to one BMv2 switch via P4Runtime gRPC."""

    def __init__(self, grpc_addr, device_id, p4info_path, bmv2_json_path):
        self.device_id = device_id
        self.grpc_addr = grpc_addr
        self.bmv2_json_path = bmv2_json_path

        # Load P4Info
        self.p4info = p4info_pb2.P4Info()
        with open(p4info_path, 'r') as f:
            text_format.Merge(f.read(), self.p4info)

        # Build name->id lookup tables
        self._table_ids = {}
        self._action_ids = {}
        self._counter_ids = {}
        self._direct_counter_ids = {}
        self._register_ids = {}
        self._mf_ids = {}
        self._ap_ids = {}

        for table in self.p4info.tables:
            tname = table.preamble.name
            self._table_ids[tname] = table.preamble.id
            self._mf_ids[tname] = {}
            for mf in table.match_fields:
                self._mf_ids[tname][mf.name] = mf.id

        for action in self.p4info.actions:
            aname = action.preamble.name
            self._action_ids[aname] = action.preamble.id
            self._ap_ids[aname] = {}
            for param in action.params:
                self._ap_ids[aname][param.name] = param.id

        for counter in self.p4info.counters:
            self._counter_ids[counter.preamble.name] = counter.preamble.id

        for counter in self.p4info.direct_counters:
            self._direct_counter_ids[counter.preamble.name] = counter.preamble.id

        for reg in self.p4info.registers:
            self._register_ids[reg.preamble.name] = reg.preamble.id

        # Connect
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self._setup_stream()

    def _setup_stream(self):
        """Establish bidirectional stream and become master."""
        def request_iterator():
            req = p4runtime_pb2.StreamMessageRequest()
            req.arbitration.device_id = self.device_id
            req.arbitration.election_id.high = 0
            req.arbitration.election_id.low = 1
            yield req

        self.stream_channel = self.stub.StreamChannel(request_iterator())

    def set_forwarding_pipeline(self):
        """Push the P4 program to the switch."""
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1
        request.action = (
            p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT)

        config = request.config
        config.p4info.CopyFrom(self.p4info)

        with open(self.bmv2_json_path, 'rb') as f:
            config.p4_device_config = f.read()

        self.stub.SetForwardingPipelineConfig(request)

    # ---- ENCODING HELPERS ----

    def _encode_value(self, value, bitwidth):
        byte_len = (bitwidth + 7) // 8
        return value.to_bytes(byte_len, byteorder='big')

    def _make_match_field(self, table_name, field_name,
                          value, prefix_len=None, mask=None):
        mf = p4runtime_pb2.FieldMatch()
        mf.field_id = self._mf_ids[table_name][field_name]

        if prefix_len is not None:
            mf.lpm.value = self._encode_value(value, 32)
            mf.lpm.prefix_len = prefix_len
        elif mask is not None:
            mf.ternary.value = self._encode_value(value, 32)
            mf.ternary.mask = self._encode_value(mask, 32)
        else:
            mf.exact.value = self._encode_value(value, 32)

        return mf

    # ---- TABLE ENTRY OPERATIONS ----

    def write_table_entry(self, table_name, match_fields,
                          action_name, action_params, priority=0):
        """Write a single table entry."""
        entry = self._build_table_entry(
            table_name, match_fields, action_name, action_params, priority)

        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(entry)

        self.stub.Write(request)

    def _build_table_entry(self, table_name, match_fields,
                           action_name, action_params, priority=0):
        entry = p4runtime_pb2.TableEntry()
        entry.table_id = self._table_ids[table_name]

        for field_name, value, extra in match_fields:
            if isinstance(extra, int) and extra <= 32:
                mf = self._make_match_field(table_name, field_name,
                                            value, prefix_len=extra)
            else:
                mf = self._make_match_field(table_name, field_name,
                                            value, mask=extra)
            entry.match.append(mf)

        action = entry.action.action
        action.action_id = self._action_ids[action_name]
        for param_name, param_value in action_params.items():
            param = action.params.add()
            param.param_id = self._ap_ids[action_name][param_name]
            if isinstance(param_value, bytes):
                param.value = param_value
            else:
                param.value = self._encode_value(param_value, 48)

        if priority > 0:
            entry.priority = priority

        return entry

    def write_table_entries_batch(self, entries):
        """Write multiple table entries atomically in one RPC.

        entries: list of (table_name, match_fields, action_name,
                 action_params, priority) tuples
        """
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1

        for table_name, match_fields, action_name, action_params, priority in entries:
            entry = self._build_table_entry(
                table_name, match_fields, action_name, action_params, priority)
            update = request.updates.add()
            update.type = p4runtime_pb2.Update.INSERT
            update.entity.table_entry.CopyFrom(entry)

        if request.updates:
            self.stub.Write(request)

    def delete_table_entry(self, table_name, match_fields, priority=0):
        """Delete a table entry by its match fields."""
        entry = p4runtime_pb2.TableEntry()
        entry.table_id = self._table_ids[table_name]

        for field_name, value, extra in match_fields:
            if isinstance(extra, int) and extra <= 32:
                mf = self._make_match_field(table_name, field_name,
                                            value, prefix_len=extra)
            else:
                mf = self._make_match_field(table_name, field_name,
                                            value, mask=extra)
            entry.match.append(mf)

        if priority > 0:
            entry.priority = priority

        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(entry)

        self.stub.Write(request)

    def delete_all_table_entries(self, table_name):
        """Delete all entries from a table."""
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        entity.table_entry.table_id = self._table_ids[table_name]

        entries_to_delete = []
        for response in self.stub.Read(request):
            for ent in response.entities:
                entries_to_delete.append(ent.table_entry)

        if not entries_to_delete:
            return

        write_req = p4runtime_pb2.WriteRequest()
        write_req.device_id = self.device_id
        write_req.election_id.high = 0
        write_req.election_id.low = 1

        for te in entries_to_delete:
            update = write_req.updates.add()
            update.type = p4runtime_pb2.Update.DELETE
            update.entity.table_entry.CopyFrom(te)

        self.stub.Write(write_req)

    # ---- COUNTER OPERATIONS ----

    def read_counter(self, counter_name, index):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        counter_entry.counter_id = self._counter_ids[counter_name]
        counter_entry.index.index = index

        for response in self.stub.Read(request):
            for entity in response.entities:
                return {
                    'packets': entity.counter_entry.data.packet_count,
                    'bytes': entity.counter_entry.data.byte_count
                }
        return {'packets': 0, 'bytes': 0}

    def read_all_table_counters(self, table_name):
        """Read all direct counter values for a table."""
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        entity.table_entry.table_id = self._table_ids[table_name]
        entity.table_entry.counter_data.CopyFrom(
            p4runtime_pb2.CounterData())

        results = []
        for response in self.stub.Read(request):
            for ent in response.entities:
                te = ent.table_entry
                results.append({
                    'packets': te.counter_data.packet_count,
                    'bytes': te.counter_data.byte_count,
                })
        return results

    # ---- REGISTER OPERATIONS ----

    def read_register(self, register_name, index):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        reg_entry = entity.register_entry
        reg_entry.register_id = self._register_ids[register_name]
        reg_entry.index.index = index

        for response in self.stub.Read(request):
            for entity in response.entities:
                data = entity.register_entry.data
                return int.from_bytes(data.bitstring, 'big')
        return 0

    def read_all_registers(self, register_name):
        """Read ALL register values using wildcard read.

        Returns dict {index: value}. Much faster than cell-by-cell.
        """
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        reg_entry = entity.register_entry
        reg_entry.register_id = self._register_ids[register_name]

        values = {}
        for response in self.stub.Read(request):
            for ent in response.entities:
                idx = ent.register_entry.index.index
                data = ent.register_entry.data
                values[idx] = int.from_bytes(data.bitstring, 'big')
        return values

    def read_register_range(self, register_name, start, count):
        """Read a range of register values. Returns list of ints."""
        values = []
        for i in range(start, start + count):
            values.append(self.read_register(register_name, i))
        return values

    def write_register(self, register_name, index, value):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1

        update = request.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        reg_entry = update.entity.register_entry
        reg_entry.register_id = self._register_ids[register_name]
        reg_entry.index.index = index
        reg_entry.data.bitstring = value.to_bytes(4, 'big')

        self.stub.Write(request)

    def reset_register(self, register_name, size):
        """Zero out all cells in a register array (batched)."""
        batch_size = 100
        for start in range(0, size, batch_size):
            request = p4runtime_pb2.WriteRequest()
            request.device_id = self.device_id
            request.election_id.high = 0
            request.election_id.low = 1

            end = min(start + batch_size, size)
            for i in range(start, end):
                update = request.updates.add()
                update.type = p4runtime_pb2.Update.MODIFY
                reg_entry = update.entity.register_entry
                reg_entry.register_id = self._register_ids[register_name]
                reg_entry.index.index = i
                reg_entry.data.bitstring = (0).to_bytes(4, 'big')

            self.stub.Write(request)

    # ---- RESOURCE USAGE ----

    def get_table_usage(self, table_name):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        entity.table_entry.table_id = self._table_ids[table_name]

        count = 0
        for response in self.stub.Read(request):
            count += len(response.entities)
        return count

    def shutdown(self):
        self.channel.close()
