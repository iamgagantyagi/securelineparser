import json
import logging
from datetime import date

logger = logging.getLogger()

class IOS_Mobile_Scanning:

    def __init__(self, cmd_args):
        self.test = "iOS Security Assessment"
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
        try:
            with open(self.file_path, 'r') as file:
                data = json.load(file)

            today = str(date.today())
            self.extract_ats_analysis(data, today)
            self.extract_binary_analysis(data, today)
            self.extract_macho_analysis(data, today)
            self.extract_dylib_analysis(data, today)
            self.extract_framework_analysis(data, today)
            self.extract_file_analysis(data, today)
            self.extract_permissions_analysis(data, today)

            self.status_mapping()

            return self.results

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data()")

    def extract_ats_analysis(self, data, today):
        if "ats_analysis" in data and "ats_findings" in data["ats_analysis"]:
            for finding in data["ats_analysis"]["ats_findings"]:
                self.results.append({
                    "Date": today,
                    "CWE/CVE": None,
                    "Severity": self.severity_mapping(finding.get("severity", None)),
                    "Title": f"{finding.get('issue', '')} | ATS Analysis",
                    "Remediation": None,
                    "Description": finding.get("description", None),
                    "ToolName": self.test
                })

    def extract_binary_analysis(self, data, today):
        if "binary_analysis" in data and "findings" in data["binary_analysis"]:
            for key, value in data["binary_analysis"]["findings"].items():
                self.results.append({
                    "Date": today,
                    "CWE/CVE": value.get("cwe", None),
                    "Severity": self.severity_mapping(value.get("severity", None)),
                    "Title": f"{key} | Binary Analysis",
                    "Remediation": None,
                    "Description": value.get("detailed_desc", None),
                    "ToolName": self.test
                })

    def extract_macho_analysis(self, data, today):
        if "macho_analysis" in data:
            macho_data = data["macho_analysis"]
            for key, value in macho_data.items():
                if key == "name":
                    continue
                self.results.append({
                    "Date": today,
                    "CWE/CVE": None,
                    "Severity": self.severity_mapping(value.get("severity", None)),
                    "Title": f"{key.replace('_', ' ').title()} | Macho Analysis",
                    "Remediation": None,
                    "Description": value.get("description", None),
                    "ToolName": self.test
                })

    def extract_dylib_analysis(self, data, today):
        if "dylib_analysis" in data:
            for dylib in data["dylib_analysis"]:
                dylib_name = dylib.get("name", "Unknown Dylib").split('/')[-1]
                for key, value in dylib.items():
                    if key == "name":
                        continue
                    title = key.replace('_', ' ').upper()
                    self.results.append({
                        "Date": today,
                        "CWE/CVE": None,
                        "Severity": self.severity_mapping(value.get("severity", None)),
                        "Title": f"{title} | Dylib Analysis | {dylib_name}",
                        "Remediation": None,
                        "Description": value.get("description", None),
                        "ToolName": self.test
                    })

    def extract_framework_analysis(self, data, today):
        if "framework_analysis" in data:
            for framework in data["framework_analysis"]:
                framework_name = framework.get("name", "Unknown Framework").split('/')[-1]
                for key, value in framework.items():
                    if key == "name":
                        continue
                    title = key.replace('_', ' ').upper()
                    self.results.append({
                        "Date": today,
                        "CWE/CVE": None,
                        "Severity": self.severity_mapping(value.get("severity", None)),
                        "Title": f"{title} | Framework Analysis | {framework_name}",
                        "Remediation": None,
                        "Description": value.get("description", None),
                        "ToolName": self.test
                    })

    def extract_file_analysis(self, data, today):
        if "file_analysis" in data:
            for file_analysis in data["file_analysis"]:
                issue = file_analysis.get("issue")
                for file in file_analysis.get("files", []):
                    file_path = file.get("file_path")
                    self.results.append({
                        "Date": today,
                        "CWE/CVE": None,
                        "Severity": self.severity_mapping(None),
                        "Title": issue,
                        "Remediation": None,
                        "Description": "Please refer to the filepath section for further analysis",
                        "FilePath": file_path,
                        "ToolName": self.test
                    })

    def extract_permissions_analysis(self, data, today):
        if "permissions" in data:
            for key, value in data["permissions"].items():
                metadata = value.get("metadata", {})
                self.results.append({
                    "Date": today,
                    "CWE/CVE": metadata.get("cwe", None),
                    "Severity": self.severity_mapping(value.get("severity", None)),
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

