import json
import logging
from datetime import date

from dateutil import parser

logger = logging.getLogger()


class TruffleHog3:

    def __init__(self, cmd_args):
        self.test = "Trufflehog3 Scan"
        self.filepath = cmd_args.path

    def get_data(self):
        try:
            logger.info(self.filepath)
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)
            list_rows = list()

            for json_data in file_data:
                if json_data.get("reason"):
                    reason = json_data["reason"]
                elif json_data.get("rule"):
                    reason = json_data["rule"]["message"]
                else:
                    raise ValueError("Format is not recognized for Trufflehog3")
                row_data = self.get_dict_data(json_data, reason)
                list_rows.append(row_data)
            logger.debug(f"Print row data: {list_rows}")
            return list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")

    def get_dict_data(self, json_data, reason):
        try:
            file = json_data["path"]
            #reason = json_data["rule"]["message"]
            cwe_id = 798
            title = "Hard Coded " + reason + " in: " + file
            remediation = "Secrets and passwords should be stored in a secure vault and/or secure storage."

            parsed_date = date.today() if json_data['date'] is None else parser.parse(json_data["date"]).date()
            logger.debug(f"Date retrieved from json file: {parsed_date}")

            description = f"[cwe-{cwe_id}] : "
            description += (
                "**Commit:** " + str(json_data.get("commit")).split("\n")[0] + "\n"
            )
            description += (
                "\n```\n"
                + str(json_data.get("commit")).replace("```", "\\`\\`\\`")
                + "\n```\n"
            )
            description += "**Reason:** " + reason + "\n"
            description += "**Path:** " + file + "\n"

            severity = "High"
            if reason == "High Entropy":
                severity = "Info"
            elif "Oauth" in reason or "AWS" in reason or "Heroku" in reason:
                severity = "Critical"
            elif reason == "Generic Secret":
                severity = "Medium"

            strings_found = ""
            if json_data.get("context"):
                for string in json_data.get("context"):   # Value of json_data["context"] is Dict
                    strings_found += string + ': ' + json_data["context"][string] + "\n"
            if len(strings_found) > 4000:
                info = (strings_found[:4000] + '..')
            else:
                info = strings_found
            description += (
                "\n**Strings Found:**\n```\n" + info + "\n```\n"
            )

            dict_data = dict()
            dict_data["Date"] = str(parsed_date)
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
