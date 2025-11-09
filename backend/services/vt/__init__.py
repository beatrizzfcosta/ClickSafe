# VirusTotal service
from .vt import (
    Virustotal,
    check_vt,
    VirustotalException,
    VirustotalError,
    VirustotalInvalidApiKey,
    VirustotalPermissionDenied,
    VirustotalRateLimit,
    VirustotalWeirdError,
)

__all__ = [
    'Virustotal',
    'check_vt',
    'VirustotalException',
    'VirustotalError',
    'VirustotalInvalidApiKey',
    'VirustotalPermissionDenied',
    'VirustotalRateLimit',
    'VirustotalWeirdError',
]
