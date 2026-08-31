from collections import OrderedDict
from typing import Optional

from ingest.pcap_reader import NormalizedPacket
from flow.flow_key import FlowKey
from flow.flow_state import FlowState


class FlowManager:

    def __init__(
        self,
        max_active_flows: int = 100_000,
        flow_timeout_sec: float = 30.0,
    ):

        self.max_active_flows = max_active_flows
        self.flow_timeout_sec = flow_timeout_sec

        self.flows: OrderedDict[
            FlowKey,
            FlowState
        ] = OrderedDict()
        self.flow_evictions = 0

    def process_packet(
        self,
        packet: NormalizedPacket,
    ) -> None:

        key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        state = self.flows.get(key)

        if state is None:

            state = FlowState(
                key=key,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
            )

            self.flows[key] = state

        state.update(packet)

        self.flows.move_to_end(key)

        self._expire_old(packet.timestamp)

        self._enforce_capacity()

    def _expire_old(
        self,
        current_timestamp: float,
    ) -> None:

        expired = []

        for key, state in self.flows.items():

            if (
                current_timestamp - state.last_seen
                > self.flow_timeout_sec
            ):
                expired.append(key)

        for key in expired:
            del self.flows[key]
            self.flow_evictions += 1

    def _enforce_capacity(self) -> None:

        while len(self.flows) > self.max_active_flows:

            self.flows.popitem(last=False)
            self.flow_evictions += 1

    def get_flow(
        self,
        key: FlowKey,
    ) -> Optional[FlowState]:

        return self.flows.get(key)

    def active_flow_count(self) -> int:

        return len(self.flows)

    def eviction_count(self) -> int:

        return self.flow_evictions
