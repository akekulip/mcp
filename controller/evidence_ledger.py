"""Sealed-epoch evidence for deterministic blackholes and calibrated gray loss.

The ledger keeps measurement validity separate from link verdicts.  A stale,
incomplete, saturated, impossible, or boundary-raced record is never converted
into a numeric loss estimate: it invalidates the current statistical sequence.

For complete exact records, the gray-loss score is a mixture e-process.  Under
the explicit null that each packet's conditional delivery probability is at
least ``healthy_delivery``, each fixed-alternative likelihood ratio has
conditional expectation at most one.  A fixed convex mixture is therefore an
e-process too, and Ville's inequality bounds the probability of ever crossing
its threshold.  Censored sequences restart under a geometric alpha-spending
schedule, whose lifetime sum is ``alpha`` within one repair generation.  No
independence or fixed stopping time is needed,
but exact uncensored counts and the stated packetwise null are required.

``BLACKHOLE`` is deliberately separate: positive departures with zero arrivals
is an immediate operational observation, not an alpha-calibrated persistence
claim.  It can trigger a reversible quarantine while the e-process continues to
record how much statistical evidence the observation carries.
"""

from dataclasses import dataclass, field
from enum import Enum
import math
from typing import Dict, Optional, Sequence, Tuple


class ReceiptStatus(Enum):
    NOT_REQUESTED = "not-requested"
    COMPLETE = "complete"
    MISSING = "missing"
    INVALID = "invalid"


class CensorReason(Enum):
    INCOMPLETE = "incomplete"
    SATURATED = "saturated"
    BOUNDARY_RACE = "boundary-race"
    COUNTER_RESET = "counter-reset"
    IMPOSSIBLE = "impossible"
    INVALID_RECEIPT = "invalid-receipt"
    EPOCH_GAP = "epoch-gap"
    STALE = "stale"
    STALE_GENERATION = "stale-generation"


class Verdict(Enum):
    IDLE = "IDLE"
    MONITOR = "MONITOR"
    GRAYHOLE = "GRAYHOLE"
    BLACKHOLE = "BLACKHOLE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class EpochRecord:
    sublink: int
    epoch: int
    tx: int
    rx: int
    gap_seen: bool = False
    receipt_status: ReceiptStatus = ReceiptStatus.NOT_REQUESTED
    censor_reason: Optional[CensorReason] = None
    repair_generation: int = 0


@dataclass(frozen=True)
class LedgerDecision:
    sublink: int
    epoch: int
    repair_generation: int
    verdict: Verdict
    e_value: float
    statistical_alarm: bool
    sequence_index: int
    sequence_alpha: float
    reason: str
    censor_reason: Optional[CensorReason] = None


@dataclass
class _CertificateState:
    repair_generation: int
    log_capitals: list
    last_epoch: Optional[int] = None
    sequence_index: int = 0


class SequentialEvidenceLedger:
    """One independent sealed sequence per behavioural sublink."""

    def __init__(self, alpha: float, healthy_delivery: float,
                 alternatives: Sequence[float], saturation: int,
                 weights: Optional[Sequence[float]] = None):
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must lie in (0, 1)")
        if not 0.0 < healthy_delivery < 1.0:
            raise ValueError("healthy_delivery must lie in (0, 1)")
        alternatives = tuple(float(value) for value in alternatives)
        if not alternatives:
            raise ValueError("at least one gray-loss alternative is required")
        if any(not 0.0 < value < healthy_delivery for value in alternatives):
            raise ValueError("every alternative must lie in (0, healthy_delivery)")
        if saturation <= 1:
            raise ValueError("saturation must exceed one")

        if weights is None:
            weights = (1.0 / len(alternatives),) * len(alternatives)
        else:
            weights = tuple(float(value) for value in weights)
        if len(weights) != len(alternatives) or any(value <= 0.0 for value in weights):
            raise ValueError("weights must be positive and match alternatives")
        total = sum(weights)
        if not math.isfinite(total) or total <= 0.0:
            raise ValueError("weights must have a finite positive sum")

        self.alpha = float(alpha)
        self.healthy_delivery = float(healthy_delivery)
        self.alternatives = alternatives
        self.weights = tuple(value / total for value in weights)
        self.saturation = int(saturation)
        self._states: Dict[int, _CertificateState] = {}

    def ingest(self, record: EpochRecord) -> LedgerDecision:
        self._validate_record(record)
        state = self._states.get(record.sublink)
        if state is None:
            state = self._new_state(record.repair_generation)
            self._states[record.sublink] = state
        elif record.repair_generation < state.repair_generation:
            return self._decision(record, state, Verdict.INCONCLUSIVE,
                                  "record belongs to an older repair generation",
                                  CensorReason.STALE_GENERATION)
        elif record.repair_generation > state.repair_generation:
            state = self._new_state(record.repair_generation)
            self._states[record.sublink] = state

        if state.last_epoch is not None and record.epoch <= state.last_epoch:
            return self._decision(record, state, Verdict.INCONCLUSIVE,
                                  "duplicate or stale epoch record",
                                  CensorReason.STALE)
        if state.last_epoch is not None and record.epoch != state.last_epoch + 1:
            self._invalidate(state, record.epoch)
            return self._decision(record, state, Verdict.INCONCLUSIVE,
                                  "one or more epochs were not sealed",
                                  CensorReason.EPOCH_GAP)

        reason = self._censor_reason(record)
        if reason is not None:
            self._invalidate(state, record.epoch)
            return self._decision(record, state, Verdict.INCONCLUSIVE,
                                  "record cannot update the statistical sequence",
                                  reason)

        state.last_epoch = record.epoch
        if record.tx == 0:
            return self._decision(record, state, Verdict.IDLE,
                                  "no departures in the sealed epoch")

        delivered = record.rx
        lost = record.tx - record.rx
        for index, alternative in enumerate(self.alternatives):
            state.log_capitals[index] += (
                delivered * math.log(alternative / self.healthy_delivery) +
                lost * math.log((1.0 - alternative) /
                                (1.0 - self.healthy_delivery))
            )

        alarm = self._log_e_value(state) >= -math.log(self._sequence_alpha(state))
        if record.rx == 0:
            return self._decision(record, state, Verdict.BLACKHOLE,
                                  "positive departures with zero arrivals")
        if alarm:
            return self._decision(record, state, Verdict.GRAYHOLE,
                                  "mixture e-value crossed the preregistered threshold")
        return self._decision(record, state, Verdict.MONITOR,
                              "valid evidence accumulated below the action threshold")

    def _new_state(self, repair_generation: int) -> _CertificateState:
        return _CertificateState(repair_generation=repair_generation,
                                 log_capitals=[0.0] * len(self.alternatives))

    def _invalidate(self, state: _CertificateState, epoch: int) -> None:
        state.log_capitals = [0.0] * len(self.alternatives)
        state.last_epoch = epoch
        state.sequence_index += 1

    def _sequence_alpha(self, state: _CertificateState) -> float:
        return self.alpha / (2.0 ** (state.sequence_index + 1))

    def _censor_reason(self, record: EpochRecord) -> Optional[CensorReason]:
        if record.censor_reason is not None:
            return record.censor_reason
        if record.tx >= self.saturation or record.rx >= self.saturation:
            return CensorReason.SATURATED
        if record.rx > record.tx:
            return CensorReason.IMPOSSIBLE
        if record.receipt_status in (ReceiptStatus.MISSING, ReceiptStatus.INVALID):
            return CensorReason.INVALID_RECEIPT
        return None

    def _log_e_value(self, state: _CertificateState) -> float:
        terms = [math.log(weight) + capital
                 for weight, capital in zip(self.weights, state.log_capitals)]
        largest = max(terms)
        return largest + math.log(sum(math.exp(value - largest) for value in terms))

    def _e_value(self, state: _CertificateState) -> float:
        log_value = self._log_e_value(state)
        if log_value >= math.log(float.fromhex("0x1.fffffffffffffp+1023")):
            return math.inf
        return math.exp(log_value)

    def _decision(self, record: EpochRecord, state: _CertificateState,
                  verdict: Verdict, reason: str,
                  censor_reason: Optional[CensorReason] = None) -> LedgerDecision:
        e_value = self._e_value(state)
        sequence_alpha = self._sequence_alpha(state)
        return LedgerDecision(
            sublink=record.sublink,
            epoch=record.epoch,
            repair_generation=state.repair_generation,
            verdict=verdict,
            e_value=e_value,
            statistical_alarm=e_value >= 1.0 / sequence_alpha,
            sequence_index=state.sequence_index,
            sequence_alpha=sequence_alpha,
            reason=reason,
            censor_reason=censor_reason,
        )

    @staticmethod
    def _validate_record(record: EpochRecord) -> None:
        if not 0 <= record.sublink < 1024:
            raise ValueError("sublink must lie in 0..1023")
        if not 0 <= record.epoch <= 0xFFFF:
            raise ValueError("epoch must fit the 16-bit hardware field")
        if record.tx < 0 or record.rx < 0:
            raise ValueError("counts must be non-negative")
        if record.repair_generation < 0:
            raise ValueError("repair_generation must be non-negative")
        if (record.censor_reason is not None and
                not isinstance(record.censor_reason, CensorReason)):
            raise ValueError("censor_reason must be a CensorReason")
        if not isinstance(record.receipt_status, ReceiptStatus):
            raise ValueError("receipt_status must be a ReceiptStatus")
