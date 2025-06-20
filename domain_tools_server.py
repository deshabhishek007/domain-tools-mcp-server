#!/usr/bin/env python3
"""
Domain Tools MCP Server

A Model Context Protocol server that provides domain analysis tools including:
- WHOIS lookups
- DNS record queries
- DNS issue detection and validation

Author: Abhishek Deshpande (https://github.com/deshabhishek007)
"""

import asyncio
import json
import sys
import socket
import dns.resolver
import dns.exception
import whois
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from mcp import ClientSession, StdioServerParameters
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types
from pydantic import AnyUrl


class DomainToolsServer:
    def __init__(self):
        self.server = Server("domain-tools")
        self.dns_resolver = dns.resolver.Resolver()
        self._setup_tools()
        
    def _setup_tools(self):
        """Set up the available tools for the MCP server."""
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available domain analysis tools."""
            return [
                types.Tool(
                    name="whois_lookup",
                    description="Get WHOIS information for a domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain name to lookup (e.g., example.com)"
                            }
                        },
                        "required": ["domain"]
                    },
                ),
                types.Tool(
                    name="dns_records",
                    description="Get DNS records for a domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain name to query"
                            },
                            "record_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "DNS record types to query (A, AAAA, MX, NS, TXT, CNAME, SOA)",
                                "default": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
                            }
                        },
                        "required": ["domain"]
                    },
                ),
                types.Tool(
                    name="dns_health_check",
                    description="Analyze DNS configuration for common issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain name to analyze"
                            }
                        },
                        "required": ["domain"]
                    },
                ),
                types.Tool(
                    name="domain_analysis",
                    description="Comprehensive domain analysis including WHOIS, DNS, and health checks",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain name to analyze completely"
                            }
                        },
                        "required": ["domain"]
                    },
                ),
            ]

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict[str, Any] | None
        ) -> list[types.TextContent]:
            """Handle tool calls."""
            if not arguments:
                raise ValueError("Missing arguments")
                
            if name == "whois_lookup":
                return await self._whois_lookup(arguments["domain"])
            elif name == "dns_records":
                record_types = arguments.get("record_types", ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
                return await self._dns_records(arguments["domain"], record_types)
            elif name == "dns_health_check":
                return await self._dns_health_check(arguments["domain"])
            elif name == "domain_analysis":
                return await self._domain_analysis(arguments["domain"])
            else:
                raise ValueError(f"Unknown tool: {name}")

    async def _whois_lookup(self, domain: str) -> list[types.TextContent]:
        """Perform WHOIS lookup for a domain."""
        try:
            # Clean domain name
            domain = domain.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            
            w = whois.whois(domain)
            
            # Format WHOIS data
            whois_data = {
                "domain": domain,
                "registrar": getattr(w, 'registrar', 'N/A'),
                "creation_date": self._format_date(getattr(w, 'creation_date', None)),
                "expiration_date": self._format_date(getattr(w, 'expiration_date', None)),
                "updated_date": self._format_date(getattr(w, 'updated_date', None)),
                "status": getattr(w, 'status', 'N/A'),
                "name_servers": getattr(w, 'name_servers', []),
                "registrant_country": getattr(w, 'country', 'N/A'),
                "registrant_org": getattr(w, 'org', 'N/A'),
            }
            
            # Calculate days until expiration
            if whois_data["expiration_date"] != "N/A":
                try:
                    exp_date = datetime.fromisoformat(whois_data["expiration_date"].replace('Z', '+00:00'))
                    days_until_expiry = (exp_date - datetime.now(timezone.utc)).days
                    whois_data["days_until_expiry"] = days_until_expiry
                except:
                    whois_data["days_until_expiry"] = "N/A"
            
            result = f"WHOIS Information for {domain}:\n\n"
            result += json.dumps(whois_data, indent=2, default=str)
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            error_msg = f"Error performing WHOIS lookup for {domain}: {str(e)}"
            return [types.TextContent(type="text", text=error_msg)]

    async def _dns_records(self, domain: str, record_types: list[str]) -> list[types.TextContent]:
        """Query DNS records for a domain."""
        try:
            domain = domain.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            
            dns_data = {"domain": domain, "records": {}}
            
            for record_type in record_types:
                try:
                    answers = self.dns_resolver.resolve(domain, record_type)
                    records = []
                    
                    for answer in answers:
                        if record_type == 'MX':
                            records.append(f"{answer.preference} {answer.exchange}")
                        elif record_type == 'SOA':
                            records.append(f"{answer.mname} {answer.rname} {answer.serial}")
                        elif record_type == 'TXT':
                            records.append(f'"{answer.to_text()}"')
                        else:
                            records.append(str(answer))
                    
                    dns_data["records"][record_type] = records
                    
                except dns.resolver.NoAnswer:
                    dns_data["records"][record_type] = []
                except dns.resolver.NXDOMAIN:
                    dns_data["records"][record_type] = ["Domain not found"]
                except Exception as e:
                    dns_data["records"][record_type] = [f"Error: {str(e)}"]
            
            result = f"DNS Records for {domain}:\n\n"
            result += json.dumps(dns_data, indent=2)
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            error_msg = f"Error querying DNS records for {domain}: {str(e)}"
            return [types.TextContent(type="text", text=error_msg)]

    async def _dns_health_check(self, domain: str) -> list[types.TextContent]:
        """Analyze DNS configuration for common issues."""
        try:
            domain = domain.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            
            issues = []
            warnings = []
            info = []
            
            # Check A records
            try:
                a_records = self.dns_resolver.resolve(domain, 'A')
                a_count = len(a_records)
                info.append(f"Found {a_count} A record(s)")
                
                if a_count == 0:
                    issues.append("No A records found - domain may not be accessible")
                elif a_count == 1:
                    warnings.append("Only one A record found - consider adding redundancy")
                    
            except dns.resolver.NXDOMAIN:
                issues.append("Domain does not exist (NXDOMAIN)")
            except Exception as e:
                issues.append(f"Error checking A records: {str(e)}")
            
            # Check MX records
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                mx_count = len(mx_records)
                info.append(f"Found {mx_count} MX record(s)")
                
                if mx_count == 0:
                    warnings.append("No MX records found - email may not work")
                elif mx_count == 1:
                    warnings.append("Only one MX record - consider adding backup MX")
                    
                # Check MX record priorities
                priorities = [mx.preference for mx in mx_records]
                if len(set(priorities)) != len(priorities):
                    warnings.append("Duplicate MX priorities found")
                    
            except dns.resolver.NoAnswer:
                warnings.append("No MX records configured")
            except Exception as e:
                issues.append(f"Error checking MX records: {str(e)}")
            
            # Check NS records
            try:
                ns_records = self.dns_resolver.resolve(domain, 'NS')
                ns_count = len(ns_records)
                info.append(f"Found {ns_count} NS record(s)")
                
                if ns_count < 2:
                    issues.append("Less than 2 NS records - DNS redundancy is insufficient")
                elif ns_count > 13:
                    warnings.append("More than 13 NS records - may cause performance issues")
                    
            except Exception as e:
                issues.append(f"Error checking NS records: {str(e)}")
            
            # Check SOA record
            try:
                soa_records = self.dns_resolver.resolve(domain, 'SOA')
                soa = soa_records[0]
                
                # Check refresh interval (should be reasonable)
                if soa.refresh > 86400:  # > 24 hours
                    warnings.append("SOA refresh interval is very high (>24h)")
                elif soa.refresh < 300:  # < 5 minutes
                    warnings.append("SOA refresh interval is very low (<5m)")
                    
                # Check retry interval
                if soa.retry > soa.refresh:
                    issues.append("SOA retry interval is greater than refresh interval")
                    
                info.append(f"SOA Serial: {soa.serial}")
                
            except Exception as e:
                issues.append(f"Error checking SOA record: {str(e)}")
            
            # Check for AAAA records (IPv6)
            try:
                aaaa_records = self.dns_resolver.resolve(domain, 'AAAA')
                info.append(f"Found {len(aaaa_records)} AAAA record(s) - IPv6 enabled")
            except dns.resolver.NoAnswer:
                warnings.append("No AAAA records found - IPv6 not configured")
            except Exception:
                pass
            
            # Check CNAME at apex
            try:
                cname_records = self.dns_resolver.resolve(domain, 'CNAME')
                if cname_records:
                    issues.append("CNAME record found at domain apex - this violates RFC standards")
            except dns.resolver.NoAnswer:
                pass  # No CNAME is good for apex
            except Exception:
                pass
            
            # Compile results
            health_report = {
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "issues": issues,
                "warnings": warnings,
                "info": info,
                "overall_status": "CRITICAL" if issues else "WARNING" if warnings else "HEALTHY"
            }
            
            result = f"DNS Health Check for {domain}:\n\n"
            result += json.dumps(health_report, indent=2)
            
            return [types.TextContent(type="text", text=result)]
            
        except Exception as e:
            error_msg = f"Error performing DNS health check for {domain}: {str(e)}"
            return [types.TextContent(type="text", text=error_msg)]

    async def _domain_analysis(self, domain: str) -> list[types.TextContent]:
        """Perform comprehensive domain analysis."""
        try:
            domain = domain.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            
            # Gather all data
            whois_result = await self._whois_lookup(domain)
            dns_result = await self._dns_records(domain, ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
            health_result = await self._dns_health_check(domain)
            
            # Combine results
            analysis_report = f"""
COMPREHENSIVE DOMAIN ANALYSIS FOR: {domain}
{'='*60}

1. WHOIS INFORMATION:
{whois_result[0].text}

2. DNS RECORDS:
{dns_result[0].text}

3. DNS HEALTH CHECK:
{health_result[0].text}

Analysis completed at: {datetime.now(timezone.utc).isoformat()}
"""
            
            return [types.TextContent(type="text", text=analysis_report)]
            
        except Exception as e:
            error_msg = f"Error performing comprehensive analysis for {domain}: {str(e)}"
            return [types.TextContent(type="text", text=error_msg)]

    def _format_date(self, date_obj) -> str:
        """Format date object to ISO string."""
        if date_obj is None:
            return "N/A"
        
        if isinstance(date_obj, list):
            date_obj = date_obj[0] if date_obj else None
            
        if date_obj is None:
            return "N/A"
            
        try:
            if isinstance(date_obj, datetime):
                return date_obj.isoformat()
            else:
                return str(date_obj)
        except:
            return "N/A"

    async def run(self):
        """Run the MCP server."""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="domain-tools",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


async def main():
    """Main entry point."""
    server = DomainToolsServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
