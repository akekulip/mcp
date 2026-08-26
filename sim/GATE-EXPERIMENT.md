# Gate experiment — implementation plan for htsim (spcl/HTSIM @ d42b1574)

**Experiment.** 3-tier fat tree, UEC transport, per-packet oblivious spraying. One
aggregation→core ("spine uplink") link silently drops data packets with probability 1e-4.
Compare three localization strategies fed by the same probe budget: **uniform** probing (every
host probes every path class equally), **random** (probes drawn at random), and **oracle** (probes
concentrated on the faulty link). Output: time-to-localize / probes-to-localize and false-positive
rate per strategy.

Nothing below is implemented; every pointer was read from the cloned source. Absolute base path
for all file references: `/home/philip/Projects/mcp/sim/htsim/htsim/sim/` (abbreviated `sim/`).

## 0. Ground truth on how packets move (what every hook hangs off)

* A packet advances hop-by-hop via `Packet::sendOn()` — `sim/network.cpp:55-85`. Normal advance
  is `nextsink = _route->at(_nexthop); _nexthop++;` (`network.cpp:73-75`), FIB fallback
  `_next_routed_hop` (`:77-78`), handoff `nextsink->receivePacket(*this);` (`:83`).
  A Route is a `vector<PacketSink*>` (`sim/route.h:20,51`); every Queue, Pipe and Switch is a
  `PacketSink` (`sim/network.h:219-235`).
* A link = `Queue` (serialisation, buffering, drops) followed by `Pipe` (propagation delay).
  The fat tree allocates every queue in `FatTreeTopology::alloc_queue`
  (`sim/datacenter/fat_tree_topology.cpp:1179-1243`; UEC default `case COMPOSITE:` `:1182-1197`)
  and every pipe inline (`fat_tree_topology.cpp:855, 879, 925, 1002`).
* Per-packet spraying entropy is chosen at the UEC source:
  `uint32_t ev = _mp->nextEntropy(...); p->set_pathid(ev);` — `sim/uec.cpp:2170-2171`; stored in
  `Packet::_pathid` (`sim/network.h:195`, accessors `:118-123`). ACK/NACK carry it back as `_ev`
  (`sim/uecpacket.h:258, 212-213`). Which physical uplink a given entropy lands on is decided in
  `FatTreeSwitch` (section 4).
* Simulation time: `EventList::now()` (`sim/eventlist.h:42`), `typedef uint64_t simtime_picosec`
  (`sim/config.h:26`), helpers `timeFromUs/timeAsUs` (`config.h:31-40`).
* RNG: the whole simulator is seeded by `-seed` → `srand(seed); srandom(seed);`
  (`sim/datacenter/main_uec.cpp:542-543`); `rng.cpp:7-27` replaces libc `rand()` with a global
  `mt19937`, and `drand()` (`sim/config.cpp:9-14`) is the [0,1] draw used inside queues already
  (`compositequeue.cpp:183`).

## 1. Per-link silent loss injection (p = 1e-4 on one spine uplink)

### 1a. Where — the Pipe exit (recommended)

`Pipe::doNextEvent()` — `sim/pipe.cpp:56-73`. The packet is popped from the in-flight ring
(`:60-62`), traffic-logged as `PKT_DEPART` (`:63`), then **`pkt->sendOn();` at `pipe.cpp:66`** is the
single line where a packet leaves the link. Silent loss = at that line, `if (_loss_prob > 0 &&
drand() < _loss_prob) { pkt->free(); _silent_drops++; } else pkt->sendOn();`. The reschedule tail
(`:68-73`, `_eventlist.sourceIsPending(*this, nexteventtime)`) must run regardless.

Why the Pipe and not the Queue: (i) a Pipe drop is invisible to the queue's ECN/trim logic and to
the `QueueLogger`, which is exactly what "silent" means; (ii) the Pipe has no other drop path, so
`_silent_drops` is unambiguous; (iii) there is a ready subclass template that overrides exactly
this exit — `CallbackPipe` (`sim/callback_pipe.h:17-23`, `sim/callback_pipe.cpp:17-42`) replaces
`sendOn()` with a callback. Model a `LossyPipe : public Pipe` on it.

Pipe API you need: ctor `Pipe(simtime_picosec delay, EventList&)` (`sim/pipe.h:24`),
`nodename()/forceName()` (`pipe.h:27-29`); `_delay` is private and `_nodename/_inflight_v` are
protected (`pipe.h:41-45`), so a subclass needs either a `set_loss_prob()` added to `Pipe` itself
or the subclass must be constructed by the topology in place of `new Pipe(...)`.

### 1b. Existing machinery to reuse or avoid

* **Count-based loss already exists in `CompositeQueue`** — `sim/compositequeue.cpp:156-161`:
  `_packet_count++; if (_is_failing && pkt.type() == UECDATA && _packet_count > _fail_rate) { _packet_count = 0; pkt.free(); return; }`
  with `set_fail_rate(int)` at `sim/compositequeue.h:58-61`. It is silent (no `logQueue`, no
  `_num_drops++`) but it is *deterministic* ("1 in every `_fail_rate+1`"), only drops UEC data,
  and is only wired for dragonfly/slimfly (`dragonfly_topology.cpp:426`, `slimfly_topology.cpp:294-299`,
  CLI `-fail-rate` in `main_uec_df.cpp:185-186` / `main_uec_sf.cpp:187-188`). **`main_uec.cpp`
  (fat tree) has no equivalent.** Cheapest possible path: give `set_fail_rate` a probabilistic
  sibling `set_loss_prob(double)` and call it on the chosen `queues_nup_nc[...]` — but a queue-side
  drop happens *before* serialisation, which slightly perturbs queue occupancy; the Pipe-side drop
  (1a) is the faithful model of a wire/optics fault. Prefer 1a; keep 1b as the fallback.
* **`-failed N` is not loss** — it degrades link speed and queue to 25 %:
  `fat_tree_topology.cpp:1174-1177` (`speed *= _failed_link_ratio; queuesize *= ...`), ratio default
  `:103-104`, CLI `main_uec.cpp:408-411`, wired `:701-703`. **Hard removal** is
  `FatTreeTopology::add_failed_link` (`fat_tree_topology.cpp:1246-1263`, NULLs
  `queues_nup_nc[switch_id][k][0]` etc. at `:1257-1262`; driven from the connection matrix at
  `main_uec.cpp:747-753`). Both are useful as *controls* (gray failure vs. hard failure vs.
  silent loss), not as the gate itself.
* **RNG isolation.** Drawing `drand()` for the loss coin consumes the global stream, so a run with
  loss will not be packet-for-packet comparable to the same-seed baseline. Give the injector its own
  `std::mt19937` seeded from `-seed` XOR a constant; keep `drand()` only if bitwise reproducibility
  against baseline is not required.

### 1c. Selecting "one spine uplink"

Container names (declared `sim/datacenter/fat_tree_topology.h:247-256`, filled
`fat_tree_topology.cpp:1002` for pipes and `:1007-1011` for queues):
`pipes_nup_nc[agg][core][bundle]` / `queues_nup_nc[agg][core][bundle]` = aggregation→core,
`pipes_nc_nup[core][agg][bundle]` / `queues_nc_nup[core][agg][bundle]` = core→aggregation.
The gate = one `(agg, core, 0)` entry of `pipes_nup_nc` (uplink direction). Add a CLI option to
`main_uec.cpp` (next to `-failed` at `:408-411`) such as `-lossy_link agg core prob`, and after the
topology is built (`main_uec.cpp:735` `topo[p] = make_unique<FatTreeTopology>(...)`) call a new
`FatTreeTopology::set_link_loss(agg, core, prob)` that reaches into `pipes_nup_nc[agg][core][0]`.
Note `add_failed_link` only touches bundle index 0 (`:1254`); do the same.

## 2. Per-link counters (tx / rx / drop)

Sites (all in the data path a UEC fat-tree run uses):

| counter | where | file:line |
|---|---|---|
| link rx (arrival at the queue) | `CompositeQueue::receivePacket` arrival hook | `sim/compositequeue.cpp:179-180` (`logTraffic(PKT_ARRIVE)` + `logQueue(PKT_ARRIVE)`) |
| link tx (departure from the queue into the pipe) | `CompositeQueue::completeService` | `sim/compositequeue.cpp:139-140` (`PKT_DEPART` then `pkt->sendOn()`); plain `Queue`: `sim/queue.cpp:154` |
| pipe rx | `Pipe::receivePacket` | `sim/pipe.cpp:19-24` |
| pipe tx | `Pipe::doNextEvent` | `sim/pipe.cpp:66` |
| **congestion drops** (visible) | `CompositeQueue` branches | `sim/compositequeue.cpp:201-205` (trim disabled), `:237-242` (header can't fit, bug: logs `pkt` not `booted_pkt`, no `_num_drops++`), `:266-276` (`pkt.free()` `:273`, `_num_drops++` `:274`), `:311-319` (high-queue overflow); plain `Queue`: `sim/queue.cpp:172-181`; `ECNQueue`: `sim/ecnqueue.cpp:50-57` (not used by the fat tree) |
| **silent drops** (the gate) | the new counter in 1a | — |
| existing per-queue counters | `num_drops()/reset_drops()` `sim/queue.h:106-107`; `num_headers/num_packets/num_stripped/num_bounced/num_acks/num_nacks/num_pulls` `sim/compositequeue.h:30-37` | |

Recommendation: do **not** scatter new counters; instead implement a `LinkStatsLogger :
public QueueLogger` (interface `virtual void logQueue(BaseQueue&, QueueEvent, Packet&) = 0;` —
`sim/loggertypes.h:102`, events `PKT_ENQUEUE/PKT_DROP/PKT_SERVICE/PKT_TRIM/PKT_BOUNCE/PKT_UNQUEUE/PKT_ARRIVE`
`:98-101`) that keeps a `map<BaseQueue*, {rx,tx,drop,trim}>`. Attach it either through the
factory the topology already calls per queue (`_logger_factory->createQueueLogger()` at
`fat_tree_topology.cpp:860-864, 908-912, 930-934, 1007-1011`; factory enum
`sim/loggers.h:98-112`) or post-hoc with `BaseQueue::setLogger(QueueLogger*)` (`sim/queue.h:28-30`).
The lossless queue family has **no** `PKT_DROP` logging at all (`queue_lossless*.cpp:67,71,90,91`) —
irrelevant unless `-queue_type lossless*` is used.

For pipe-level tx/rx (needed to see the silent drop as rx−tx on that link) add two counters to
`Pipe` or to the `LossyPipe` subclass; there is no logger hook in `Pipe` beyond the flow-level
`logTraffic(PKT_DEPART)` at `pipe.cpp:63`.

## 3. Packet-logging hook (to attribute every packet to a link and an entropy)

* Flow-level trace: `TrafficLogger::logTraffic(Packet&, Logged& location, TrafficEvent)` —
  `sim/loggertypes.h:90-95` (events `PKT_ARRIVE, PKT_DEPART, PKT_CREATESEND, PKT_DROP, ...`). Every
  queue/pipe calls `pkt.flow().logTraffic(pkt, *this, ev)`, so a custom `TrafficLogger` attached to
  the probe flows' `PacketFlow` sees each hop with `location.nodename()`; combine with
  `pkt.pathid()` (`sim/network.h:118`) and `previousHop()/currentHop()` (`network.h:100-101`).
* Record sink: `Logfile::writeRecord(type,id,ev,val1,val2,val3)` (`sim/logfile.h:43-47`, created
  `main_uec.cpp:594`); reference implementation `QueueLoggerSimple::logQueue`
  (`sim/loggers.cpp:61-68`). New logger types need a new `Logger::EventType` value
  (`sim/loggertypes.h:56-74`).
* Names: `Logged::str()/setName()` (`sim/loggertypes.h:35-51`), queues `setName` appends
  (`sim/queue.h:31-38`); IDs from `Logged::get_id()` (`loggertypes.h:42`, counter
  `network.cpp:323`).

## 4. Epoch callback for the measurement scheduler

Subclass `EventSource` — declaration `sim/eventlist.h:13-23`:
`EventSource(EventList&, const string& name)`, pure `virtual void doNextEvent() = 0;`,
`virtual bool isTraffic() {return true;}`. Schedule with
`EventList::sourceIsPending(EventSource&, simtime_picosec when)` (`sim/eventlist.h:31`, def
`eventlist.cpp:84-93`, asserts `when >= now()` and silently ignores `when >= _endtime`) or
`sourceIsPendingRel(src, dt)` (`eventlist.h:33-34`); cancel/reschedule at `eventlist.h:35-40`.
Pattern to copy: the periodic samplers `QueueLoggerSampling` / `SinkLoggerSampling`
(`sim/loggers.h:141-147, 199-206`) — they re-arm themselves in `doNextEvent()` and return
`isTraffic()=false`. **Caveat:** the live `sourceIsPending` (`eventlist.cpp:84-93`) ignores
`isTraffic()` (the version honouring it is commented out at `:71-82`), so a periodic epoch timer
keeps the simulation alive until `-end`; make it stop re-arming when the workload is done
(e.g. when `UecSrc` flow-completion count reaches the total, or on a `-end`).

An `EpochScheduler : EventSource` therefore: (1) on each `doNextEvent()` reads the `LinkStatsLogger`
map (section 2) and the probe outcomes (section 5), (2) runs the uniform/random/oracle policy to pick
next-epoch probe paths, (3) injects the probes, (4) re-arms with `sourceIsPendingRel(*this, epoch)`.
`main_uec.cpp` already has a `-logtime` sampling hook you can mirror for the CLI.

SECTIONS_5_TO_7_PLACEHOLDER
