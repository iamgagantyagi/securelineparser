from datetime import date
import json
import logging
from lib.db_utils import CIS_Controls_Mappings

logger = logging.getLogger()


class CISAudit:

    def __init__(self, cmd_args, pg_connection, input_json):
        self.test = cmd_args.test_name
        self.filepath = cmd_args.path
        self.os_version = None
        self.pg_connection = pg_connection
        self.input_json = input_json

    def get_data(self):
        try:
            logger.info(self.filepath)
            # Get the ip and system details from json file
            sys_details = self.filepath.split("_")
            self.os_version = sys_details[-3]
            logger.info(f"printing: {sys_details}")
            
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)
            list_rows = list()

            controls_manager = CIS_Controls_Mappings(self.pg_connection, self.input_json.get("postgres_cis_controls_table"))
            controls_mappings = controls_manager.fetch_cis_controls()
            for json_data in file_data["results"]:
                row_data = self.get_dict_data(json_data, controls_mappings)
                if row_data.get("CIS_Control") is not None:
                    list_rows.append(row_data)
            logger.debug(f"Print row data: {list_rows}")
            return list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")

    def extract_control_title(self, data):
        try:
            parts = data.split('|', 1)
            control = parts[0].strip()
            title = parts[1].strip()
            return control, title
        except Exception as e:
            logger.error(f'Exception occurred in extract_control_title() for "{data}": {e}')
            return None, data


    def get_dict_data(self, json_data, controls_mappings):
        try:
            # Returns the current local date
            today = date.today()
            logger.debug(f"Today's date is: {today}")

            cwe_id = None
            control, title = self.extract_control_title(json_data["title"])
            is_success = json_data["successful"]
            logger.info("Fetching Remediation Result")

            logger.info(f"printing: {self.os_version.lower()}")
            remediation = "Expected : "
            if self.os_version.lower() == "ubuntu22":
                if json_data["matcher-result"]:
                    remediation += f"{json_data['matcher-result']['expected']}"
            elif json_data["expected"]:
                for text in json_data["expected"]:
                    remediation += "\n" + text
            logger.debug(f"Remediation info: {remediation}")

            remediation += "\nPlease check the description for more details about the command(s)"

            description = json_data["summary-line"]

            severity = controls_mappings.get(control, "Medium")

            dict_data = dict()
            dict_data["Date"] = str(today)
            dict_data["CWE/CVE"] = cwe_id
            dict_data["ToolName"] = self.test
            dict_data["Severity"] = severity
            dict_data["CIS_Control"] = control
            dict_data["Title"] = title + "| " + str(is_success)
            dict_data["Remediation"] = remediation
            dict_data["Description"] = description
            logger.debug(f"Print row data: {dict_data}")
            return dict_data

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")
