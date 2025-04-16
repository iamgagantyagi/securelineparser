import sys
import logging
import re
import xml.etree.ElementTree as ET
from dateutil import parser  # Unused for now, but retained if you need datetime parsing

sys.path.append('/root/.pyenv/versions/3.9.17/lib/python3.9/site-packages')

logger = logging.getLogger()


class OpenVas:
    mapping_severity = {
        "info": "Info",
        "low": "Low",
        "moderate": "Medium",
        "medium": "Medium",
        "high": "High",
        "critical": "High",
        "log": "Info"
    }

    def __init__(self, cmd_args):
        self.test = "OpenVAS"
        self.filepath = cmd_args.path

    def map_vulnerability_data(self, result, test):
        try:
            vuln_data = {}

            title = result.findtext("name")
            threat = result.findtext("original_threat")
            summary = result.findtext("summary", "").strip()
            tags_text = result.findtext(".//nvt/tags") or ""
            tags_dict = dict(tag.split("=", 1) for tag in tags_text.split("|") if "=" in tag)

            insight = tags_dict.get("insight", "").strip()
            impact = tags_dict.get("impact", "").strip()
            summary = tags_dict.get("summary", summary).strip()
            solution = tags_dict.get("solution", "").strip()

            host = result.findtext("host", "")
            port = result.findtext("port", "")

            # Extract CVE
            cve_id = ""
            for ref in result.findall(".//ref"):
                if ref.attrib.get("type") == "cve":
                    cve_id = ref.attrib.get("id")
                    if cve_id:
                        break

            if not cve_id:
                match = re.search(r'cve=(CVE-\d{4}-\d+)', tags_text, re.IGNORECASE)
                if match:
                    cve_id = match.group(1)

            # Extract CWE
            cwe_id = ""
            for ref in result.findall(".//ref"):
                if ref.attrib.get("type") == "url":
                    url = ref.attrib.get("id", "")
                    match = re.search(r'/definitions/(\d+)\.html', url)
                    if match:
                        cwe_id = f"CWE-{match.group(1)}"
                        break

            severity_normalized = self.mapping_severity.get(threat.lower(), "Medium") if threat else "Medium"
            if severity_normalized == "Info":
                solution = "Remediation is not applicable for vulnerabilities with an informational severity."

            # Final mapping
            vuln_data["Severity"] = severity_normalized
            vuln_data["Remediation"] = solution
            vuln_data["Description"] = f"{insight} | {impact}" if insight and impact else summary
            vuln_data["Title"] = title
            vuln_data["Component"] = f"{host} | Port - {port}"
            vuln_data["CWE/CVE"] = cve_id or cwe_id
            vuln_data["ToolName"] = test

            return vuln_data

        except Exception as e:
            logger.warning(f"Error mapping vulnerability data: {e}")
            return None

    def get_data(self):
        """Parses the XML file and returns a list of mapped vulnerability data."""
        try:
            vulnerabilities_list = []

            with open(self.filepath, 'r') as file:
                xml_content = file.read()

            root = ET.fromstring(xml_content)
            for result in root.findall(".//result"):
                vuln_data = self.map_vulnerability_data(result, self.test)
                if vuln_data:
                    vulnerabilities_list.append(vuln_data)

            return vulnerabilities_list

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data(): {e}")
            raise
