from datetime import date
import json
import logging

logger = logging.getLogger()


class CISAudit:

    def __init__(self, cmd_args):
        self.test = cmd_args.test_name
        self.filepath = cmd_args.path
        self.os_version = None

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

            for json_data in file_data["results"]:
                row_data = self.get_dict_data(json_data)
                list_rows.append(row_data)
            logger.debug(f"Print row data: {list_rows}")
            return list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")

    def get_dict_data(self, json_data):
        try:
            # Returns the current local date
            today = date.today()
            logger.debug(f"Today's date is: {today}")

            cwe_id = "Unknown"
            title = json_data["title"]
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

            severity = "Unknown"

            dict_data = dict()
            dict_data["Date"] = str(today)
            dict_data["CWE/CVE"] = cwe_id
            dict_data["ToolName"] = self.test
            dict_data["Severity"] = severity
            dict_data["Title"] = title
            dict_data["Remediation"] = remediation
            dict_data["Description"] = description
            logger.debug(f"Print row data: {dict_data}")
            return dict_data

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")
