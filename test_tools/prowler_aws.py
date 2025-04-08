import json
import logging
from datetime import date

logger = logging.getLogger()

class Prowler_AWS:

    def __init__(self, cmd_args):
        self.test = "AWS Cloud Security Audit"
        self.file_path = cmd_args.path
        self.results = list()
        self.seen_entries = set() 

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
            for item in data:
                self.extract_findings(item, today)

            return self.results

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data()")

    def extract_findings(self, item, today):
        title = item.get("finding_info", {}).get("title", "")
        region = ""
        if "resources" in item and isinstance(item["resources"], list) and len(item["resources"]) > 0:
            region = item["resources"][0].get("region", "")
        risk_details = item.get("risk_details", "")
        remediation_data = item.get("remediation", "")
        desc = remediation_data.get("desc", "")
        references = " | ".join(remediation_data.get("references", []))

        remediation = f"{desc} | {references}" if references else desc
        status_code = item.get("status_code", "").capitalize()
        severity = self.severity_mapping(item.get("severity", None))
        region = ""
        component = ""

        if "resources" in item and isinstance(item["resources"], list) and len(item["resources"]) > 0:
            region = item["resources"][0].get("region", "")
            group_name = item["resources"][0].get("group", {}).get("name", "")
        else:
            group_name = ""

        event_code = item.get("metadata", {}).get("event_code", "")

        component = group_name if group_name else event_code

        formatted_title = f"{title} | {region}" if region else title
        component = group_name if group_name else event_code

        entry_key = (formatted_title, status_code, severity, component, risk_details)

        if entry_key in self.seen_entries:
            return
        self.seen_entries.add(entry_key)

        self.results.append({
            "Date": today,
            "Title": formatted_title,
            "Description": risk_details,
            "Remediation": remediation,
            "Status": status_code,
            "Severity": severity,
            "Component": component,
            "ToolName": self.test
        })


