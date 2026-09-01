from __future__ import annotations
from contextlib import contextmanager
import copy
import socket
import threading
from typing import Any, Callable, Dict, List, Optional
from schemas.security import SecurityBoundaryEvent, SecurityBoundaryEventType
from ingest.pcap_reader import NormalizedPacket

class PassiveSecurityViolation(RuntimeError):
    pass

class PassiveRuntimeGuard:
    passive_only: bool = True
    network_write_allowed: bool = False
    payload_decryption_allowed: bool = False
    active_mitigation_allowed: bool = False

    def __init__(self, raise_on_violation: bool = False):
        self.raise_on_violation = raise_on_violation
        self.security_events: List[SecurityBoundaryEvent] = []
        self._lock = threading.Lock()

    def record_violation(self, event_type: SecurityBoundaryEventType, component: str, operation: str, reason: str, source_context: Optional[Dict[str, Any]] = None) -> SecurityBoundaryEvent:
        evt = SecurityBoundaryEvent(
            event_type=event_type,
            component=component,
            operation=operation,
            allowed=False,
            reason=reason,
            source_context=source_context or {},
        )
        with self._lock:
            self.security_events.append(evt)
        if self.raise_on_violation:
            raise PassiveSecurityViolation('Security boundary blocked: ' + reason)
        return evt

    def guard_network_write(self, operation: str, destination: str, component: str = 'PassiveRuntimeGuard', context: Optional[Dict[str, Any]] = None) -> bool:
        ctx = dict(context or {})
        ctx['destination'] = destination
        self.record_violation(
            event_type=SecurityBoundaryEventType.NETWORK_WRITE_BLOCKED,
            component=component,
            operation=operation,
            reason='PS 26145 passive one-way observation required. Outbound network writes forbidden.',
            source_context=ctx,
        )
        return False

    def guard_active_response(self, action: str, target_entity: str, component: str = 'PassiveRuntimeGuard', context: Optional[Dict[str, Any]] = None) -> bool:
        ctx = dict(context or {})
        ctx['target_entity'] = target_entity
        ctx['action'] = action
        self.record_violation(
            event_type=SecurityBoundaryEventType.ACTIVE_RESPONSE_BLOCKED,
            component=component,
            operation='mitigation.' + action,
            reason='Inline active mitigation disabled. Monitoring enclave operates strictly out-of-band.',
            source_context=ctx,
        )
        return False

    def guard_payload_decryption(self, stream_id: str, component: str = 'PassiveRuntimeGuard', context: Optional[Dict[str, Any]] = None) -> bool:
        ctx = dict(context or {})
        ctx['stream_id'] = stream_id
        self.record_violation(
            event_type=SecurityBoundaryEventType.PAYLOAD_DECRYPTION_BLOCKED,
            component=component,
            operation='payload.decrypt',
            reason='Encrypted traffic analysis is strictly metadata-only. Payload decryption forbidden.',
            source_context=ctx,
        )
        return False

    def assert_immutable_packet(self, packet: NormalizedPacket) -> NormalizedPacket:
        return copy.copy(packet)

    @contextmanager
    def intercept_network_egress(self):
        orig_send = socket.socket.send
        orig_sendto = socket.socket.sendto
        orig_sendall = socket.socket.sendall
        orig_connect = socket.socket.connect
        guard = self

        def safe_send(sock_self, data, *args, **kwargs):
            guard.guard_network_write('socket.send', str(sock_self), 'PassiveRuntimeGuard', {'bytes': len(data)})
            return len(data)

        def safe_sendto(sock_self, data, *args, **kwargs):
            guard.guard_network_write('socket.sendto', str(args[0] if args else 'unknown'), 'PassiveRuntimeGuard', {'bytes': len(data)})
            return len(data)

        def safe_sendall(sock_self, data, *args, **kwargs):
            guard.guard_network_write('socket.sendall', str(sock_self), 'PassiveRuntimeGuard', {'bytes': len(data)})
            return None

        def safe_connect(sock_self, address):
            guard.guard_network_write('socket.connect', str(address), 'PassiveRuntimeGuard', {'target': str(address)})
            raise ConnectionRefusedError('Outbound connection blocked by passive boundary policy.')

        try:
            socket.socket.send = safe_send
            socket.socket.sendto = safe_sendto
            socket.socket.sendall = safe_sendall
            socket.socket.connect = safe_connect
            yield self
        finally:
            socket.socket.send = orig_send
            socket.socket.sendto = orig_sendto
            socket.socket.sendall = orig_sendall
            socket.socket.connect = orig_connect
