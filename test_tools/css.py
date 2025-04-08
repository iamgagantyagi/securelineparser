import json
import logging
from datetime import date

from dateutil import parser

logger = logging.getLogger()


class CloudSecuritySuite:

    def __init__(self, cmd_args):
        self.test = "Cloud Security Suite"
        self.filepath = cmd_args.path

    def get_data(self):
        try:
            logger.info(self.filepath)
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)
            list_rows = list()

            for report_data in file_data.get("report"):
                finding_list = report_data.get("data")
                title = report_data.get("check")
                for data in finding_list:
                    row_data = self.get_dict_data(data, title)
                    list_rows.append(row_data)
            logger.debug(f"Print row data: {list_rows}")
            return list_rows
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
                    # logger.warning(
                    #     f"Warning: Unknown severity value detected '{severity}'. Bypass to 'Medium' value"
                    # )
                    severity = "Medium"
                else:
                    severity = mapping_severity[severity.strip().lower()]
            else:
                severity = "Medium"
            return severity
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.severity_mapping() : {e}")
            raise Exception(f"Exception occurred in {__name__}.severity_mapping() ")

    def status_mapping(self, status):
        try:
            status_map = {
                "WARNING": "Fail",
                "INFO": "Pass",
                "PASS": "Pass",
            }
            return status_map.get(status.upper(), "Pass")
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.status_mapping() : {e}")
            raise Exception(f"Exception occurred in {__name__}.status_mapping() ")

    def get_dict_data(self, data, title):
        try:
            
            dict_data = dict()
            dict_data["ToolName"] = self.test
            dict_data["Severity"] = self.severity_mapping(data.get("type"))
            dict_data["Title"] = title
            dict_data["Remediation"] = None
            dict_data["Description"] = f'{data.get("value", "")} | {data.get("region", "")}'
            dict_data["Status"] = self.status_mapping(data.get("type"))
            logger.debug(f"Print row data: {dict_data}")
            return dict_data
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")
