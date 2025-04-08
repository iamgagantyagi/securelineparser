import json
import logging
from datetime import date

logger = logging.getLogger()


class Trivy_CIS:

    def __init__(self, cmd_args):
        self.test = "Trivy_CIS"
        self.filepath = cmd_args.path
        self.list_rows = list()

    def get_data(self):
        try:
            logger.info(self.filepath)
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)

            for json_data in file_data['Results']:
                self.get_dict_data(json_data)
            return self.list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")
        
    
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


    def create_dict_data(self, cwe, severity, title, remediation, description):
        """Helper function to create dictionary for row data."""
        return {
            "Date": str(date.today()),
            "CWE/CVE": cwe,
            "ToolName": self.test,
            "Severity": self.severity_mapping(severity),
            "Title": title,
            "Remediation": remediation,
            "Description": description,
            "SystemInfo": ""
        }

    def get_dict_data(self, json_data):
        try:
            if json_data['Results'] is None:
                json_data['remediation'] = "No remediation is required as the check is passed"
                dict_data = self.create_dict_data(
                    json_data['ID'],
                    json_data['Severity'],
                    json_data['Name'],
                    json_data['remediation'],
                    json_data['Description']
                )
                self.list_rows.append(dict_data)
            else:
                for result in json_data['Results']:
                    if 'Vulnerabilities' in result.keys():
                        for vulnerability in result['Vulnerabilities']:
                            json_data['remediation'] = "This vulnerability is already detected in the Trivy image vulnerability scan"
                            dict_data = self.create_dict_data(
                                json_data['ID'],
                                vulnerability['Severity'],
                                vulnerability['Title'],
                                json_data['remediation'],
                                vulnerability['Description']
                                )
                            self.list_rows.append(dict_data)
                    elif 'Misconfigurations' in result.keys():
                        for misconfig in result['Misconfigurations']:
                            dict_data = self.create_dict_data(
                                json_data['ID'],
                                misconfig['Severity'],
                                misconfig['Title'],
                                misconfig['Resolution'],
                                misconfig['Description']
                                )
                            self.list_rows.append(dict_data)
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")

