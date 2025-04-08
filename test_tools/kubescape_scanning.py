import logging
import xml.etree.ElementTree as XmlTree
from datetime import date
from urllib.request import Request, urlopen
import re


logger = logging.getLogger()


class KubeScape:
    mapping_severity = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}

    def __init__(self, cmd_args):
        self.test = cmd_args.test_name
        self.filepath = cmd_args.path
    

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


    def get_severity(self, url_link):
        severity = ['Critical', 'High', 'Medium', 'Low']
        url = Request(url=url_link, headers={'User-Agent': 'Mozilla/5.0'})
        html_content = urlopen(url).read().decode("utf-8")

        # initializing tag for "p" to check severity
        for sev in severity:
            reg_str = "<p>" + sev + "</p>"
            find_string = re.search(reg_str, html_content)
            if find_string is not None:
                return self.severity_mapping(sev)
        return self.severity_mapping("Unknown")
    
    def remove_special_chars(self, input):
        # Remove problematic characters at the start
        if input:
            return re.sub(r"^[=\-\+\*/\'@\s]+", "", input)

    def get_data(self):
        try:
            tree = XmlTree.parse(self.filepath)
            logger.debug(f"print {tree}")
            items_list = list()
            unique_items = set()

            today = date.today()
            logger.debug(f"Today's date is: {today}")

            cwe_id = None

            for node in tree.findall("testsuite"):
                logger.debug(f"print testsuite info : {node}")
                for item in node.findall("testcase"):
                    logger.debug(f"Print testcase info: {item}")
                    if not item.findall("failure"):
                        continue
                    for fail_msg in item.findall("failure"):
                        msg = fail_msg.get("message")
                        logger.debug(f"print title for failed tests: {msg}")
                        title = item.get("name")
                        logger.debug(f"Print title {title}")

                        # Retrieve ID and URL for description
                        url = " ".join(ls for ls in msg.split(" ") if ls.startswith("https"))
                        desc = url.split("\n")[0]
                        description = "ID: " + desc.split('/')[-1] + " \n" + desc
                        logger.debug(f"description: {description}")

                        # Get the severity from html report
                        severity = self.get_severity(desc)

                        dict_msg = {}
                        # Split failure message to get remediation, kind,name and namespace
                        resource_definitions = 'resource_definitions'
                        for line in msg.splitlines():
                            if ":" in line:
                                key, value = line.split(":", 1)
                                key = key.strip()
                                value = value.strip()
                                
                                if key == 'apiVersion':
                                    if resource_definitions not in dict_msg:
                                        dict_msg[resource_definitions] = []
                                    dict_msg[resource_definitions].append(f"{key}: {value}")
                                else:
                                    dict_msg[key] = value

                        logger.debug(f"Print dict list : {dict_msg}")
                        remediation = dict_msg["Remediation"]
                        logger.debug(f"Print remediation {remediation}")
                        for resource_definition in dict_msg.get(resource_definitions, []):
                            items = dict()
                            parts = resource_definition.split(";")
                            parsed_resource = {}
                            
                            for part in parts:
                                if ":" in part:
                                    key, value = part.split(":", 1)
                                    parsed_resource[key.strip()] = value.strip()
                            
                            api_version = self.remove_special_chars(parsed_resource.get("apiVersion"))
                            kind = parsed_resource.get("kind")
                            namespace = parsed_resource.get("namespace")
                            name = parsed_resource.get("name")
                            logger.debug(f"Print kind: {kind}, namespace: {namespace}, name: {name},")

                            items["Date"] = str(today)
                            items["CWE/CVE"] = cwe_id
                            items["Severity"] = severity
                            items["ToolName"] = self.test
                            items["Title"] = title
                            items["Description"] = description
                            items["Remediation"] = remediation
                            items["SystemInfo"] = self.remove_special_chars(namespace)
                            items["Kind"] = self.remove_special_chars(kind)
                            items["Namespace"] = self.remove_special_chars(namespace)
                            items["Name"] = self.remove_special_chars(name)

                            unique_key = (api_version, items["Kind"], items["Name"], items["Namespace"], items["Severity"], items["Description"])
                            if unique_key not in unique_items:
                                unique_items.add(unique_key)
                                items_list.append(items)

            logger.info(items_list)
            return items_list

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")
