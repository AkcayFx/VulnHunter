"""Professional tool wrappers — require Docker sandbox mode."""
from vulnhunter.tools.pro.nmap_scan import NmapScanTool
from vulnhunter.tools.pro.nuclei_scan import NucleiScanTool
from vulnhunter.tools.pro.ffuf_scan import FfufScanTool
from vulnhunter.tools.pro.sqlmap_scan import SqlmapScanTool
from vulnhunter.tools.pro.nikto_scan import NiktoScanTool
from vulnhunter.tools.pro.httpx_probe import HttpxProbeTool
from vulnhunter.tools.pro.subfinder_enum import SubfinderEnumTool
from vulnhunter.tools.pro.katana_crawl import KatanaCrawlTool

PRO_TOOLS: list[type] = [
    NmapScanTool,
    NucleiScanTool,
    FfufScanTool,
    SqlmapScanTool,
    NiktoScanTool,
    HttpxProbeTool,
    SubfinderEnumTool,
    KatanaCrawlTool,
]

__all__ = ["PRO_TOOLS"]
