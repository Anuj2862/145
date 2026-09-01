from __future__ import annotations
import json
import os
import pytest
import socket
from schemas.security import SecurityBoundaryEvent, SecurityBoundaryEventType
from pipeline.passive_guard import PassiveRuntimeGuard, PassiveSecurityViolation
from evaluation.security.workspace_guard import audit_repository_structure, validate_target_path, detect_reparse_points_and_cycles
from evaluation.security.security_auditor import SecurityBoundaryAuditor
from evaluation.runners.m22_security_runner import run_m22_security_benchmark
from ingest.pcap_reader import NormalizedPacket

def test_no_network_writes_in_runtime():
    guard = PassiveRuntimeGuard()
    assert guard.passive_only is True
    assert guard.network_write_allowed is False
    with guard.intercept_network_egress():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.send(b'test_payload')
    assert len(guard.security_events) == 1
    evt = guard.security_events[0]
    assert evt.event_type == SecurityBoundaryEventType.NETWORK_WRITE_BLOCKED
    assert evt.allowed is False

def test_active_response_unavailable_and_blocked():
    guard = PassiveRuntimeGuard()
    assert guard.active_mitigation_allowed is False
    res = guard.guard_active_response('block_ip', '203.0.113.5')
    assert res is False
    assert len(guard.security_events) == 1
    evt = guard.security_events[0]
    assert evt.event_type == SecurityBoundaryEventType.ACTIVE_RESPONSE_BLOCKED
    assert evt.allowed is False

def test_passive_ingest_only_no_return_path():
    auditor = SecurityBoundaryAuditor()
    ingest_res = auditor.audit_passive_ingest_and_replay()
    assert ingest_res['status'] == 'PASS'
    assert ingest_res['one_way_passive_model'] is True
    assert ingest_res['write_source'] == 'None'

def test_no_tls_payload_decryption_metadata_only():
    auditor = SecurityBoundaryAuditor()
    tls_res = auditor.audit_tls_decryption()
    assert tls_res['status'] == 'PASS'
    assert tls_res['runtime_decryption_matches'] == 0
    assert tls_res['metadata_only_verified'] is True

def test_pcap_replay_is_read_only():
    from pipeline.replay import BoundedPacketQueue, replay_pcap
    q = BoundedPacketQueue(capacity=100)
    assert not hasattr(q, 'send_socket')
    assert not hasattr(q, 'raw_socket')
    assert hasattr(q, 'put')
    assert hasattr(q, 'get')

def test_source_observations_remain_immutable():
    guard = PassiveRuntimeGuard()
    pkt = NormalizedPacket(
        timestamp=1756680000.0,
        src_ip='192.168.1.50',
        dst_ip='10.0.0.1',
        src_port=50000,
        dst_port=80,
        protocol=6,
        packet_length=500,
        sensor_id='test-sensor',
    )
    safe = guard.assert_immutable_packet(pkt)
    assert safe is not pkt
    assert safe.src_ip == pkt.src_ip

def test_api_cannot_invoke_network_mitigation():
    auditor = SecurityBoundaryAuditor()
    api_res = auditor.audit_api_surface()
    assert api_res['status'] == 'PASS'
    assert api_res['actuation_endpoints'] == 0

def test_nested_git_detection():
    ws = audit_repository_structure()
    assert ws['git_directories_count'] == 1
    assert ws['status'] == 'PASS'

def test_nested_project_detection():
    ws = audit_repository_structure()
    assert len(ws['forbidden_entries_found']) == 0
    assert '145' not in ws['forbidden_entries_found']
    with pytest.raises(ValueError):
        validate_target_path('D:/SIH/145_v2/145/test_file.py', 'D:/SIH/145_v2')

def test_junction_symlink_cycle_detection():
    res = detect_reparse_points_and_cycles('.')
    assert res['cycle_detected'] is False

def test_canonical_git_root_validation():
    ws = audit_repository_structure()
    assert ws['repository_root'].endswith('145_v2')
    assert ws['git_branch'] == 'member-1/phase2-upgrade'

def test_generated_output_path_validation():
    valid_path = validate_target_path('evaluation/reports/test_report.json')
    assert os.path.isabs(valid_path)
    with pytest.raises(ValueError):
        validate_target_path('../unsafe_file.txt')

def test_m22_runner_report_artifacts_generation():
    report = run_m22_security_benchmark()
    assert report['milestone'] == 'M22'
    assert report['verdict']['security_boundary_verdict'] == 'PASS'
    assert os.path.exists('evaluation/reports/M22_SECURITY_BOUNDARY_REPORT.json')
    assert os.path.exists('evaluation/reports/M22_SECURITY_BOUNDARY_REPORT.md')
