"""Nuclei Integration Engine — AI-driven template selection, parsing, and scan planning."""
from vulnhunter.nuclei.parser import NucleiResult, parse_and_convert, parse_nuclei_results
from vulnhunter.nuclei.profiles import (
    SCAN_PROFILES,
    ScanProfile,
    get_profile,
    get_tags_for_tech,
    get_templates_for_tech,
)
from vulnhunter.nuclei.template_manager import NucleiScanPlan, NucleiTemplateManager

__all__ = [
    "NucleiResult",
    "NucleiScanPlan",
    "NucleiTemplateManager",
    "ScanProfile",
    "SCAN_PROFILES",
    "get_profile",
    "get_tags_for_tech",
    "get_templates_for_tech",
    "parse_and_convert",
    "parse_nuclei_results",
]
