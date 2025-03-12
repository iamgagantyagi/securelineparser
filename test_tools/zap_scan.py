import logging
import xml.etree.ElementTree as XmlTree

from dateutil import parser
from html2text import html2text


logger = logging.getLogger()


class ZapScan:
    mapping_severity = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}

    def __init__(self, cmd_args):
        self.test = "ZAP Scan"
        self.filepath = cmd_args.path

    def get_data(self):
        try:
            tree = XmlTree.parse(self.filepath)
            items_list = list()
            # Need to get the report generated date from xml field
            report_date = tree.getroot().get('generated')
            parsed_date = parser.parse(report_date).date()
            logger.info(f"Date retrieved from xml file: {parsed_date}")
            for node in tree.findall("site"):
                for item in node.findall("alerts/alertitem"):
                    items = dict()
                    title = item.findtext("alert")
                    description = html2text(item.findtext("desc"))
                    remediation = html2text(item.findtext("solution"))

                    items["Date"] = str(parsed_date)

                    if item.findtext("cweid") is not None and item.findtext("cweid").isdigit():
                        items["CWE/CVE"] = int(item.findtext("cweid"))
                        description += "desc: " + html2text(item.findtext("desc")) + "\n"

                    items["ToolName"] = self.test
                    items["Severity"] = self.mapping_severity.get(item.findtext("riskcode"))
                    items["Title"] = title
                    items["Remediation"] = remediation
                    items["Description"] = description
                    items_list.append(items)
            logger.info(items_list)

            return items_list
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")
