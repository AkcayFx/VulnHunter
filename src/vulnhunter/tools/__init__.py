"""Tool system for VulnHunter — Python-native and professional scanning tools."""
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.port_scanner import PortScannerTool
from vulnhunter.tools.header_analyzer import HeaderAnalyzerTool
from vulnhunter.tools.ssl_checker import SSLCheckerTool
from vulnhunter.tools.dns_enum import DNSEnumTool
from vulnhunter.tools.whois_lookup import WhoisLookupTool
from vulnhunter.tools.dir_brute import DirBruteforceTool
from vulnhunter.tools.cve_lookup import CVELookupTool
from vulnhunter.tools.web_vuln import WebVulnScannerTool
from vulnhunter.tools.web_scraper import WebScraperTool
from vulnhunter.tools.shodan_search import ShodanSearchTool
from vulnhunter.tools.search_engine import SearchEngineTool
from vulnhunter.tools.subdomain_enum import SubdomainEnumTool
from vulnhunter.tools.tech_fingerprint import TechFingerprintTool
from vulnhunter.tools.url_harvester import URLHarvesterTool
from vulnhunter.tools.js_analyzer import JSAnalyzerTool
from vulnhunter.tools.param_discovery import ParamDiscoveryTool
from vulnhunter.tools.takeover_check import SubdomainTakeoverTool
from vulnhunter.tools.cors_check import CORSCheckTool
from vulnhunter.tools.ssrf_detector import SSRFDetectorTool
from vulnhunter.tools.idor_detector import IDORDetectorTool
from vulnhunter.tools.host_header import HostHeaderTool
from vulnhunter.tools.access_control import AccessControlTool
from vulnhunter.tools.graphql_test import GraphQLTestTool
from vulnhunter.tools.pro import PRO_TOOLS

NATIVE_TOOLS: list[type[BaseTool]] = [
    PortScannerTool,
    HeaderAnalyzerTool,
    SSLCheckerTool,
    DNSEnumTool,
    WhoisLookupTool,
    DirBruteforceTool,
    CVELookupTool,
    WebVulnScannerTool,
    WebScraperTool,
    ShodanSearchTool,
    SearchEngineTool,
    SubdomainEnumTool,
    TechFingerprintTool,
    # Phase 3: Bug Bounty Recon Pipeline
    URLHarvesterTool,
    JSAnalyzerTool,
    ParamDiscoveryTool,
    SubdomainTakeoverTool,
    CORSCheckTool,
    # Phase 5: Advanced Vulnerability Detection
    SSRFDetectorTool,
    IDORDetectorTool,
    HostHeaderTool,
    AccessControlTool,
    GraphQLTestTool,
]

ALL_TOOLS: list[type[BaseTool]] = NATIVE_TOOLS + PRO_TOOLS

__all__ = ["BaseTool", "NATIVE_TOOLS", "PRO_TOOLS", "ALL_TOOLS"]
