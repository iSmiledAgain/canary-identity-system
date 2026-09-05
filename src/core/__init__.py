"""Core detection engine for the Canary Identity System."""

from .analyzer import AnalyzedEvent, analyze_event, analyze_many
from .config import Config
from .incident import Incident, build_incident
from .models import CanaryEvent
from .profiler import ActorProfile, profile_actor
from .timeline import Timeline, reconstruct

__all__ = [
    "ActorProfile",
    "AnalyzedEvent",
    "CanaryEvent",
    "Config",
    "Incident",
    "Timeline",
    "analyze_event",
    "analyze_many",
    "build_incident",
    "profile_actor",
    "reconstruct",
]
