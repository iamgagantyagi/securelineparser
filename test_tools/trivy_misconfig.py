import logging
import re
import json
from datetime import date

logger = logging.getLogger()


class Trivy_MisConfig:

    def __init__(self, cmd_args):
        self.test = "Trivy_MisConfig"
        self.file_path = cmd_args.path
        self.results = list()


    def severity_mapping(self, severity):
        mapping_severity = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "High",
        }

        try:
            if severity:
                if severity.strip().lower() not in mapping_severity:
                    logger.warning(
                        f"Warning: Unknown severity value detected '{severity}'. Bypass to 'Medium' value"
                    )
                    severity = "Medium"
                else:
                    severity = mapping_severity[severity.strip().lower()]
            else:
                severity = "Medium"
            return severity
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.severity_mapping() : {e}")
            raise Exception(f"Exception occurred in {__name__}.severity_mapping() ")


    def get_data(self):
        """Reads the file and parses its content into structured data."""
        try:
            with open(self.file_path, 'r') as f:
                content = f.read().strip()

            corrected_json = f"[{content.rstrip(',')}]"
            file_data = json.loads(corrected_json)

            for data in file_data:
                filepath = data.get("ArtifactName")
                results = data.get("Results", [])
                for result in results:
                    misconfig_list = result.get("Misconfigurations", [])
                    for misconfig in misconfig_list:
                        row_data = dict()
                        row_data["Date"] = date.today()
                        row_data["CWE/CVE"] = None
                        row_data["ToolName"] = self.test
                        row_data["Severity"] = self.severity_mapping(misconfig.get("Severity"))
                        row_data["Title"] = misconfig.get("Title")
                        row_data["Remediation"] = misconfig.get("Resolution")
                        row_data["Description"] = misconfig.get("Description")
                        row_data["Type"] = misconfig.get("Type")
                        row_data["Status"] = misconfig.get("Status")
                        row_data["FilePath"] = filepath
                        row_data["Namespace"] = misconfig.get("Namespace")
                        self.results.append(row_data)
            return self.results

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data()")
    
    @staticmethod
    def clean_description(description):
        """
        Cleans the description by removing unnecessary characters and retaining only the meaningful text.
        """
        # Remove unwanted characters like '═', '─', '[', and trailing/leading spaces
        cleaned_description = re.sub(r"[═─\[\]]+", "", description).strip()
        return cleaned_description
