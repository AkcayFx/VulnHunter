"""Nuclei scan profiles and technology-to-template mapping.

Maps discovered tech stacks to the most relevant Nuclei template directories,
so the AI doesn't blast all 8000+ templates blindly.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanProfile:
    """A predefined Nuclei scan configuration."""

    name: str
    description: str
    args: tuple[str, ...] = ()
    max_duration_seconds: int = 600


SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan — critical/high HTTP vulns only",
        args=("-severity", "critical,high", "-type", "http"),
        max_duration_seconds=120,
    ),
    "web-full": ScanProfile(
        name="web-full",
        description="Full web scan — medium+ HTTP vulnerabilities",
        args=("-severity", "medium,high,critical", "-type", "http"),
        max_duration_seconds=600,
    ),
    "cves-only": ScanProfile(
        name="cves-only",
        description="Known CVEs only — medium+ severity",
        args=("-t", "http/cves/", "-severity", "medium,high,critical"),
        max_duration_seconds=600,
    ),
    "misconfig": ScanProfile(
        name="misconfig",
        description="Misconfigurations and exposed services",
        args=("-t", "http/misconfiguration/", "-t", "http/exposures/"),
        max_duration_seconds=300,
    ),
    "takeover": ScanProfile(
        name="takeover",
        description="Subdomain takeover detection",
        args=("-t", "http/takeovers/"),
        max_duration_seconds=120,
    ),
    "default-creds": ScanProfile(
        name="default-creds",
        description="Default login credentials on admin panels",
        args=("-t", "http/default-logins/"),
        max_duration_seconds=300,
    ),
    "exposed-panels": ScanProfile(
        name="exposed-panels",
        description="Exposed admin panels and dashboards",
        args=("-t", "http/exposed-panels/"),
        max_duration_seconds=180,
    ),
    "tokens": ScanProfile(
        name="tokens",
        description="Exposed tokens, API keys, and secrets",
        args=("-t", "http/token-spray/", "-t", "http/exposures/tokens/"),
        max_duration_seconds=180,
    ),
    "full": ScanProfile(
        name="full",
        description="All templates — comprehensive but slow",
        args=(),
        max_duration_seconds=1800,
    ),
}

# ---------------------------------------------------------------------------
# Technology → Nuclei template mapping
#
# When recon discovers a technology, we map it to the most relevant template
# directories and tags. This makes scanning 10x faster and more targeted.
# ---------------------------------------------------------------------------

TECH_TEMPLATE_MAP: dict[str, list[str]] = {
    # Web servers
    "apache": ["http/cves/apache/", "http/misconfiguration/apache/"],
    "nginx": ["http/cves/nginx/", "http/misconfiguration/nginx/"],
    "iis": ["http/cves/iis/", "http/misconfiguration/iis/"],
    "tomcat": ["http/cves/apache/tomcat/", "http/default-logins/apache/tomcat/"],
    "lighttpd": ["http/cves/lighttpd/"],
    "caddy": ["http/cves/caddy/"],

    # CMS / Frameworks
    "wordpress": ["http/cves/wordpress/", "http/vulnerabilities/wordpress/", "http/default-logins/wordpress/"],
    "joomla": ["http/cves/joomla/", "http/vulnerabilities/joomla/"],
    "drupal": ["http/cves/drupal/", "http/vulnerabilities/drupal/"],
    "magento": ["http/cves/magento/"],
    "shopify": ["http/cves/shopify/"],
    "laravel": ["http/cves/laravel/", "http/exposures/configs/laravel/"],
    "django": ["http/cves/django/", "http/exposures/configs/django/"],
    "flask": ["http/cves/flask/"],
    "spring": ["http/cves/spring/", "http/cves/springboot/"],
    "rails": ["http/cves/rails/"],
    "express": ["http/cves/express/"],
    "nextjs": ["http/cves/nextjs/"],
    "nuxt": ["http/cves/nuxt/"],

    # Languages / runtimes
    "php": ["http/cves/php/", "http/vulnerabilities/php/"],
    "java": ["http/cves/java/", "http/cves/apache/"],
    "nodejs": ["http/cves/nodejs/"],
    "python": ["http/cves/python/"],
    "aspnet": ["http/cves/aspnet/"],

    # Databases
    "mysql": ["http/cves/mysql/", "network/cves/mysql/"],
    "postgresql": ["http/cves/postgresql/", "network/cves/postgresql/"],
    "mongodb": ["http/cves/mongodb/", "network/cves/mongodb/"],
    "redis": ["http/cves/redis/", "network/cves/redis/"],
    "elasticsearch": ["http/cves/elasticsearch/", "http/misconfiguration/elasticsearch/"],
    "couchdb": ["http/cves/couchdb/"],

    # Panels / Admin tools
    "phpmyadmin": ["http/cves/phpmyadmin/", "http/default-logins/phpmyadmin/"],
    "grafana": ["http/cves/grafana/", "http/default-logins/grafana/"],
    "jenkins": ["http/cves/jenkins/", "http/default-logins/jenkins/"],
    "gitlab": ["http/cves/gitlab/", "http/default-logins/gitlab/"],
    "sonarqube": ["http/cves/sonarqube/"],
    "kibana": ["http/cves/kibana/", "http/exposed-panels/kibana/"],
    "rabbitmq": ["http/cves/rabbitmq/", "http/default-logins/rabbitmq/"],
    "prometheus": ["http/exposed-panels/prometheus/"],

    # Cloud / Infrastructure
    "aws": ["http/cves/aws/", "http/misconfiguration/aws/", "http/exposures/configs/aws/"],
    "azure": ["http/cves/azure/", "http/misconfiguration/azure/"],
    "gcp": ["http/cves/google/", "http/misconfiguration/google/"],
    "docker": ["http/cves/docker/", "http/exposed-panels/docker/"],
    "kubernetes": ["http/cves/kubernetes/", "http/exposed-panels/kubernetes/"],

    # Networking / VPN
    "fortinet": ["http/cves/fortinet/", "network/cves/fortinet/"],
    "paloalto": ["http/cves/paloalto/"],
    "citrix": ["http/cves/citrix/"],
    "sonicwall": ["http/cves/sonicwall/"],
    "f5": ["http/cves/f5/"],

    # APIs / Services
    "graphql": ["http/misconfiguration/graphql/", "http/exposures/apis/graphql/"],
    "swagger": ["http/exposures/apis/swagger/", "http/misconfiguration/swagger/"],
    "api": ["http/exposures/apis/"],
}

# Tags that map to nuclei -tags flag (broader matching)
TECH_TAG_MAP: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-plugin"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "spring": ["spring", "springboot"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "aws": ["aws", "amazon"],
    "graphql": ["graphql"],
}


def get_templates_for_tech(technologies: list[str]) -> list[str]:
    """Given a list of discovered technologies, return relevant Nuclei template paths."""
    templates: list[str] = []
    seen: set[str] = set()

    for tech in technologies:
        tech_lower = tech.lower().strip()
        for key, paths in TECH_TEMPLATE_MAP.items():
            if key in tech_lower:
                for p in paths:
                    if p not in seen:
                        templates.append(p)
                        seen.add(p)

    return templates


def get_tags_for_tech(technologies: list[str]) -> list[str]:
    """Given a list of discovered technologies, return relevant Nuclei tags."""
    tags: list[str] = []
    seen: set[str] = set()

    for tech in technologies:
        tech_lower = tech.lower().strip()
        for key, tag_list in TECH_TAG_MAP.items():
            if key in tech_lower:
                for tag in tag_list:
                    if tag not in seen:
                        tags.append(tag)
                        seen.add(tag)

    return tags


def get_profile(name: str) -> ScanProfile:
    """Retrieve a scan profile by name, falling back to 'quick'."""
    return SCAN_PROFILES.get(name, SCAN_PROFILES["quick"])
