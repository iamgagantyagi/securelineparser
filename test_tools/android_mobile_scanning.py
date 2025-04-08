import json
import logging
from datetime import date

logger = logging.getLogger()

class Android_Mobile_Scanning:

    def __init__(self, cmd_args):
        self.test = "Android Security Assessment"
        self.file_path = cmd_args.path
        self.results = list()


    def severity_mapping(self, severity):
        mapping_severity = {
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "High",
            "dangerous": "High",
            "info": "Info",
            "secure": "Info"
        }
        try:
            if severity:
                if severity.strip().lower() not in mapping_severity:
                    severity = "Medium"
                else:
                    severity = mapping_severity[severity.strip().lower()]
            else:
                severity = "Medium"
            return severity
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.severity_mapping() : {e}")
            raise Exception(f"Exception occurred in {__name__}.severity_mapping()")
    
    def get_data(self):
        """Reads the JSON file and extracts structured data."""
        try:
            with open(self.file_path, 'r') as file:
                data = json.load(file)

            today = str(date.today())
            
            # Extract findings from various sections
            self.extract_certificate_analysis(data, today)
            self.extract_manifest_analysis(data, today)
            self.extract_binary_analysis(data, today)
            self.extract_code_analysis(data, today)
            self.extract_permissions_analysis(data,today)

            self.status_mapping()

            return self.results

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data()")

    
    def extract_certificate_analysis(self, data, today):
        if "certificate_analysis" in data and "certificate_findings" in data["certificate_analysis"]:
            for finding in data["certificate_analysis"]["certificate_findings"]:
                severity = self.severity_mapping(finding[0])
                self.results.append({
                    "Date": today,
                    "CWE/CVE": None,
                    "Severity": severity,
                    "Title": f"{finding[2]} | Certificate Analysis",
                    "Remediation": None,
                    "Description": finding[1],
                    "ToolName": self.test
                })


    def extract_manifest_analysis(self, data, today):
        if "manifest_analysis" in data and "manifest_findings" in data["manifest_analysis"]:
            for finding in data["manifest_analysis"]["manifest_findings"]:
                self.results.append({
                    "Date": today,
                    "CWE/CVE": None,
                    "Severity": self.severity_mapping(finding.get("severity", None)),
                    "Title": f"{finding.get('title', None)} | Manifest Analysis",
                    "Remediation": None,
                    "Description": finding.get("description", None),
                    "ToolName": self.test
                })


    def extract_binary_analysis(self, data, today):
        if "binary_analysis" in data:
            for binary in data["binary_analysis"]:
                binary_name = binary.get("name", "Unknown binary").split('/')[-1]
                for key, value in binary.items():
                    if key == "name":
                        continue
                    if isinstance(value, dict) and "severity" in value and "description" in value:
                        self.results.append({
                            "Date": today,
                            "CWE/CVE": None,
                            "Severity": self.severity_mapping(value.get("severity", None)),
                            "Title": f"{key.replace('_', ' ').title()} | Binary Analysis | {binary_name}",
                            "Remediation": None,
                            "Description": value.get("description", None),
                            "ToolName": self.test
                        })


    def extract_code_analysis(self, data, today):
        if "code_analysis" in data and "findings" in data["code_analysis"]:
            for key, value in data["code_analysis"]["findings"].items():
                metadata = value.get("metadata", {})
                self.results.append({
                    "Date": today,
                    "CWE/CVE": metadata.get("cwe", None),
                    "Severity": self.severity_mapping(metadata.get("severity", None)),
                    "Title": f"{key.replace('_', ' ').title()} | Code Analysis",
                    "Remediation": metadata.get("ref", None),
                    "Description": metadata.get("description", None),
                    "ToolName": self.test
                })
    
    def extract_permissions_analysis(self, data, today):
        if "permissions" in data:
            for key, value in data["permissions"].items():
                metadata = value.get("metadata", {})
                self.results.append({
                    "Date": today,
                    "CWE/CVE": metadata.get("cwe", None),
                    "Severity": self.severity_mapping(value.get("status")),
                    "Title": f"{key.replace('_', ' ').title()} | Application Permissions",
                    "Remediation": metadata.get("ref", None),
                    "Description": value.get("description"),
                    "ToolName": self.test
                })

    def status_mapping(self):
        try:
            for result in self.results:
                severity = result.get("Severity", "info").lower()
                status = "Fail" if severity in ["high", "critical", "dangerous", "warning"] else "Pass"
                result["Status"] = status
                logger.info(f"Inserted result into DB: {result}")
        except Exception as e:
            logger.fatal(f"Exception occurred while storing results in DB: {e}")
            raise Exception("Failed to store results in DB")
