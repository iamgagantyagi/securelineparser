import re
import requests
import logging
from datetime import date
logger = logging.getLogger()

class Sonarqube:

    def __init__(self, cmd_args):
        self.test = "sonarqube"
        self.base_url = cmd_args.base_url
        self.project_key = cmd_args.project_key
        self.project_branch = cmd_args.project_branch
        self.user_token = cmd_args.user_token

    def text_cleaning(self,text):
        processed_text = re.sub(r'<[^>]+>|[\n\r]', ' ', text)
        for match in re.finditer(r'<a\s+href=[\'"]?([^\'" >]+)[\'"]?[^>]*>(.*?)<\/a>', text):
            href = match.group(1)
            link_text = match.group(2)
            processed_text = processed_text.replace(link_text, f"{link_text}({href})")
            processed_text = re.sub(r'\s+', ' ', processed_text.strip())
        
        return processed_text
    
    def extract_cwe(self,text):
        pattern = r'(CWE-\d+)'
        matches = re.findall(pattern, text)
        return matches

    def extracting_rules_data(self, key:str):
        try:
            url = f"{self.base_url}/api/rules/show"
            headers = {
                "Authorization": f"Bearer {self.user_token}"
            }
            params = {
                "key": key
            }
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            rule_response = response.json()

            
            ToolName = "sonarqube"
            severity = rule_response['rule']['severity']
            title = rule_response['rule']['name']
            today = date.today()
            for val in rule_response['rule']['descriptionSections']:
                if val["key"] == 'root_cause':
                    root_cause_description = self.text_cleaning(val["content"])
                    break
                else:
                    root_cause_description = "" 

            for val in rule_response['rule']['descriptionSections']:           
                if val["key"] == 'resources':
                    resources_description = self.text_cleaning(val["content"]) 
                    break
                else:
                    resources_description=""   

            cwe_codes = self.extract_cwe(resources_description)

            if cwe_codes:
                cwe = cwe_codes[0]
            else:
                cwe = "unknown"

            description = root_cause_description + resources_description  
            remediation = self.text_cleaning(rule_response['rule']['descriptionSections'][0]["content"])

            # Creating a dictionary
            issues_data = {
                "Date":today,
                "CWE/CVE": cwe,
                "ToolName": ToolName,
                "Severity": severity,
                "Title": title,
                "Description":description,
                "Remediation":remediation
            }

            return issues_data

        except Exception as e:
            # logger.exception(f"Exception occurred in extracting_rules_data: {e}")
            raise e  

    def get_data(self):
        try:
            url = f"{self.base_url}/api/issues/list"
            headers = {
                "Authorization": f"Bearer {self.user_token}"
            }
            params = {
                "project": self.project_key,
                "branch": self.project_branch
            }
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            issues_data = response.json()
            
            issues_data_list = []
            # Parse the response and extract relevant information about each issue
            for issue in issues_data["issues"]:
                issues_data_list.append(self.extracting_rules_data(issue["rule"]))

            return issues_data_list    

        except Exception as e:
            # logger.exception(f"Exception occurred in get_data: {e}")
            raise e 
