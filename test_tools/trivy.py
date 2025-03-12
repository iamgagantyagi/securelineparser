import json
import logging
from datetime import date

logger = logging.getLogger()


class Trivy:

    def __init__(self, cmd_args):
        self.test = "Trivy"
        self.filepath = cmd_args.path

    def get_data(self):
        try:
            logger.info(self.filepath)
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)
            list_rows = list()
            file_data = file_data["Results"]
            system_info = file_data[0]['Target']
            for json_data in file_data:
                if json_data.get('Vulnerabilities') is None:
                    continue
                for vulnerability in json_data['Vulnerabilities']:
                    row_data = self.get_dict_data(vulnerability)
                    row_data["SystemInfo"] = system_info
                    list_rows.append(row_data)
            logger.debug(f"Print row data: {list_rows}")
            return list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")

    def get_dict_data(self, json_data):
        try:
            today = date.today()
            logger.debug(f"Today's date is: {today}")
            cwe_ids = json_data['CweIDs'] if json_data.get('CweIDs') else ''
            cwe = f"{json_data['VulnerabilityID']}, {cwe_ids}" if cwe_ids else json_data['VulnerabilityID']
            severity = json_data['Severity']
            title_text = json_data['Title'].split(':')[1].strip() if ':' in json_data['Title'] else json_data['Title']
            title = f"PkgName: {json_data['PkgName']}\n{title_text}"

            description = json_data['Description'] if json_data.get('Description') else 'UNKNOWN'
            references = json_data['References'] if json_data.get('References') else 'UNKNOWN'
            full_description = f"{description}\n\nReferences: "
            for reference in references:
                full_description += '\n' + reference
            remediation_text = (
                "You should update the component to latest stable version or consider using an "
                "alternative to ensure security."
            )
            remediation = (
                f"FixedVersion: {json_data['FixedVersion']}" if json_data.get('FixedVersion') else remediation_text
            )
            dict_data = dict()
            dict_data["Date"] = str(today)
            dict_data["CWE/CVE"] = cwe
            dict_data["ToolName"] = self.test
            dict_data["Severity"] = severity
            dict_data["Title"] = title
            dict_data["Remediation"] = remediation
            dict_data["Description"] = full_description
            logger.debug(f"Print row data: {dict_data}")
            return dict_data
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")
