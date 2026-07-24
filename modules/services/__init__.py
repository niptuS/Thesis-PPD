"""
Entrada: None
Salida: Service layer (modules.services)
Descripción: Service layer extracted from the former LiveExecutionEngine
             monolith. Each service has a single responsibility and can be
             unit-tested independently:

             - CaptureService           : PCAP capture (tcpdump/tshark/dumpcap)
             - EventExecutor            : fires benign & attack events
             - FlowExtractor            : PCAP → raw flow rows (NFStream/tshark)
             - FlowLabeler              : flow rows → labeled flows (scientific decision)
             - ArtifactManifestWriter   : metadata JSON + execution log
"""
from __future__ import annotations

from modules.services.capture_service import CaptureService
from modules.services.event_executor import EventExecutor
from modules.services.flow_extractor import FlowExtractor
from modules.services.flow_labeler import FlowLabeler
from modules.services.artifact_manifest_writer import ArtifactManifestWriter

__all__ = [
    "CaptureService",
    "EventExecutor",
    "FlowExtractor",
    "FlowLabeler",
    "ArtifactManifestWriter",
]
