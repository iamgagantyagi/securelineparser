import base64
import requests
import re
import json
import math
from enum import Enum
from dateutil import parser
import logging

logger = logging.getLogger()

TRACE = False


class MetaConstants(Enum):
    HOTSPOTS = "SECURITYHOTSPOT"
    VULNERABILITY = "VULNERABILITY"
    TOOLNAME = "SonarQube"
    CODESMELL = "MAINTAINABILITY"
    RELIABILITY = "RELIABILITY"


SUPPORTED_ENUMS = [MetaConstants]
PAGE_SIZE = 500  # Keeping it max available

SECURITY_HOTSPOT = {
    "profile": "SecurityHotSpot",
    "fetch": {
        "type": "API",
        "url": "{base_url}/api/hotspots/search?inNewCodePeriod=false&onlyMine=false&p={page}&project={project}&ps={page_size}&status=TO_REVIEW",
        "path": ["hotspots"],
        "pagination_key": "hotspots",
        "inputs": ["project"],
        "filter": [("Component", ["component"]),
                   ("Project", ["project"]),
                   ("Type", MetaConstants.HOTSPOTS),
                   ("ToolName", MetaConstants.TOOLNAME),
                   ("SecurityCategory", ["securityCategory"]),
                   ("Severity", ["vulnerabilityProbability"]),
                   ("Line", ["line"]),
                   ("Title", ["message"]),
                   ("Rule", ["ruleKey"]),
                   ("Date", ["updateDate"]),
                   ("Status", ["status"])]
    },
    "enrich_each": [
        {
            "url": "{base_url}/api/hotspots/show?hotspot={key}",
            "path": "",
            "inputs": ["key"],
            "filter": [("FilePath", ["component", "path"]),
                       ("Key", ["key"]),
                       ("Description", ["rule", "vulnerabilityDescription"]),
                       ("Remediation", ["rule", "fixRecommendations"])]
        }
    ],
    "post_process": "default_formatter"
}

MAINTAINABILITY = {
    "profile": "Maintainability",
    "fetch": {
        "type": "API",
        "url": "{base_url}/api/issues/search?components={project}&s=FILE_LINE&impactSoftwareQualities=MAINTAINABILITY&issueStatuses=OPEN%2CCONFIRMED&ps={page_size}&p={page}&additionalFields=_all&timeZone=Asia%2FCalcutta",
        "path": ["issues"],
        "pagination_key": "issues",
        "inputs": ["project"],
        "filter": [("Component", ["component"]),
                   ("Project", ["project"]),
                   ("ToolName", MetaConstants.TOOLNAME),
                   ("Severity", ["severity"]),
                   ("FilePath", ["component"]),
                   ("Line", ["line"]),
                   ("Title", ["message"]),
                   ("Rule", ["rule"]),
                   ("Type", MetaConstants.CODESMELL),
                   ("Date", ["updateDate"]),
                   ("Status", ["status"])]

    },
    "enrich_each": [
        {
            "url": "{base_url}/api/rules/show?key={rule}",
            "path": "",
            "inputs": ["rule"],
            "filter": [("Description", ["rule", "htmlDesc"])]

        }
    ],
    "post_process": "maintainability_formatter"
}

RELIABILITY = {
    "profile": "Reliability",
    "fetch": {
        "type": "API",
        "url": "{base_url}/api/issues/search?components={project}&s=FILE_LINE&impactSoftwareQualities=RELIABILITY&issueStatuses=CONFIRMED%2COPEN&ps={page_size}&p={page}&facets=cleanCodeAttributeCategories%2CimpactSoftwareQualities%2CcodeVariants&additionalFields=_all&timeZone=Asia%2FCalcutta",
        "path": ["issues"],
        "pagination_key": "issues",
        "inputs": ["project"],
        "filter": [("Component", ["component"]),
                   ("Project", ["project"]),
                   ("ToolName", MetaConstants.TOOLNAME),
                   ("Type", MetaConstants.RELIABILITY),
                   ("Severity", ["severity"]),
                   ("FilePath", ["component"]),
                   ("Line", ["line"]),
                   ("Title", ["message"]),
                   ("Rule", ["rule"]),
                   ("Date", ["updateDate"]),
                   ("Status", ["status"])]

    },
    "enrich_each": [
        {
            "url": "{base_url}/api/rules/show?key={rule}",
            "path": "",
            "inputs": ["rule"],
            "filter": [("Description", ["rule", "htmlDesc"]),
                       ("Name", ["rule", "name"]),
                       ("Key", ["rule", "key"])]

        }
    ],
    "post_process": "reliability_formatter"
}

VULNERABILITY_API = {
    "profile": "Vulnerabilities",
    "fetch": {
        "type": "API",
        "url": "{base_url}/api/issues/search?components={project}&s=FILE_LINE&impactSoftwareQualities=SECURITY&issueStatuses=CONFIRMED%2COPEN&ps={page_size}&p={page}&facets=cleanCodeAttributeCategories%2CimpactSoftwareQualities%2CcodeVariants&additionalFields=_all&timeZone=Asia%2FCalcutta",
        "path": ["issues"],
        "pagination_key": "issues",
        "inputs": ["project"],
        "filter": [("Component", ["component"]),
                   ("Project", ["project"]),
                   ("ToolName", MetaConstants.TOOLNAME),
                   ("Severity", ["severity"]),
                   ("Line", ["line"]),
                   ("Title", ["message"]),
                   ("Rule", ["rule"]),
                   ("Type", MetaConstants.VULNERABILITY),
                   ("Date", ["updateDate"])
                   ]
    },
    "enrich_each": [
        {
            "url": "{base_url}/api/rules/show?key={rule}",
            "path": "",
            "inputs": ["rule"],
            "filter": [("Name", ["rule", "name"]),
                       ("Description", ["rule", "htmlDesc"]),
                       ("Severity", ["rule", "severity"])]
        }
    ],
    "post_process": "vulnerability_formatter"
}

ALL_PROFILES = [SECURITY_HOTSPOT, VULNERABILITY_API, MAINTAINABILITY, RELIABILITY]
#ALL_PROFILES = [RELIABILITY]


def remove_nl(text):
    if text is None or not isinstance(text, str) or not text.strip():
        return "For more details, please refer to the scan report."
    return text.replace('\n', ' ')


def __nested_dict_fetch(source, *keys, **kwargs):
    """
    This is keeping it simple but for more advanced extract, check jmespath, jsonpath_ng
    python libraries that can work on iterators inside dictionary as well..
    """
    default = kwargs.get('default', None)
    current = source
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current

def get_base64_trace(trace):
    return base64.b64encode(json.dumps(trace).encode('utf-8')).decode('utf-8')


def severity_mapping(severity):
        mapping_severity = {
        "minor": "Low",
        "info": "Low",
        "major": "Medium",
        "blocker": "High",
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


def default_formatter(data, **kwargs):
    data["Severity"] = severity_mapping(data["Severity"])
    data["Date"] = str(parser.parse(data["Date"]).date())
    data["Description"] = remove_nl(data["Description"])
    data["Remediation"] = remove_nl(data["Remediation"])
    if TRACE:
        trace_data = get_base64_trace({
            "_parent": data["_parent"],
            "_detail": data["_detail"]
        })
        data["Trace"] = str(trace_data)
    data.pop("_parent", None)
    data.pop("_detail", None)
    return data


def __default_remediation_link_formatter(issue_type, data, **kwargs):
    remediation_url_base = "https://rules.sonarsource.com/{language}/"
    rspec_suffix = "RSPEC-{spec_number}/"
    tokens = data["Rule"].split(":")
    language = str(__nested_dict_fetch(data, "_detail", "rule", "langName")).lower()
    # TODO: Check with SME If we get more than 2 Tokens, do we point to a generic URL ?
    spec_no = ''.join([char for char in tokens[1] if char.isdigit()])
    url_inputs = {"language": language, "spec_number": spec_no, "issue_type": issue_type} ## Currently skipping issuetype
    if not spec_no:
        data["Remediation"] = remediation_url_base.format(**url_inputs)
    else:
        data["Remediation"] = (remediation_url_base + rspec_suffix).format(**url_inputs)
    return default_formatter(data)


def vulnerability_formatter(data, **kwargs):
    return __default_remediation_link_formatter("vulnerability", data, **kwargs)


def maintainability_formatter(data, **kwargs):
    return __default_remediation_link_formatter("code%20smell", data, **kwargs)


def reliability_formatter(data, **kwargs):
    return __default_remediation_link_formatter("bug", data, **kwargs)

"""
Post Process methods end
"""


class SonarQubeAPIClient:
    def __init__(self, config):
        self.token = config.pop("auth_token")
        self.config = config
        self.headers = {"Authorization": f"Bearer {self.token}", "Content-type": "application/json"}

    @staticmethod
    def get_next_pages(page_size, total, is_first_processed=True):
        """
        We keep the pageSize constant and don't change it everytime.
        """

        """
        This is a current limitation, where more than 10000 records cannot be 
        processed by API. For this, the original API query that generates
        total record should be modified to only return 10000 or less, this
        could be done by smartly doing dynamic query filters that would bring the records
        down and then iterate over that BUT cannot guarantee such filters for query could be 
        found.
        """
        if total > 9999:
            logger.warning(f"!!!!! Limited data records reported due to current query limitation. Found {total} but reporting only 9999")
            total = 9999
        pages = math.ceil(total / page_size)
        if not pages:
            return []
        if is_first_processed:
            return [page for page in range(2, pages + 1)]
        else:
            return [page for page in range(1, pages + 1)]

    def get_response(self, url):
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def gather_paginated_response(self, url, pagination_key, params):
        all_response = {}
        params["page"] = 1
        formatted_url = url.format(**params)
        initial_response = self.get_response(formatted_url)
        if "paging" not in initial_response:
            raise Exception("API set for pagination but no paging key found")
        page_size = initial_response["paging"]["pageSize"]
        total = initial_response["paging"]["total"]
        # Cache the initial response
        all_response[pagination_key] = initial_response[pagination_key]
        next_pages_list = SonarQubeAPIClient.get_next_pages(page_size, total)
        logger.info(f"Pagesize {page_size} Total -{total} Next Pages list {next_pages_list}")
        for page in next_pages_list:
            logger.info(f"processing page {page}")
            params["page"] = page
            formatted_url = url.format(**params)
            response = self.get_response(formatted_url)
            # previous_responses = all_response[pagination_key]
            # all_response[pagination_key] = previous_responses.extend()
            all_response[pagination_key].extend(response[pagination_key])
        return all_response

    def get_api_response(self, url, paginate, paginate_on, **kwargs):
        """
        Currently only designed for the GET with the URL parameters
        formatted with given kwargs. Fails if the URL params don't exist
        """
        params = {**kwargs, **self.config}
        formatted_url = url.format(**params)
        if not paginate:
            return self.get_response(formatted_url)
        return self.gather_paginated_response(url, paginate_on, params)


class SonarProfileExtract:

    def __init__(self, api_client: SonarQubeAPIClient, profile, profile_inputs):
        self.api_client = api_client
        self.profile = profile
        self.profile_inputs = profile_inputs

    def __nested_fetch(self, source, *keys, **kwargs):
        """
        This is keeping it simple but for more advanced extract, check jmespath, jsonpath_ng
        python libraries that can work on iterators inside dictionary as well..
        """
        default = kwargs.get('default', None)
        current = source
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current

    def get_profile_data(self):
        logger.info(f"Processing data for profile {self.profile.get('profile')}")
        data = self.__fetch_profile_api_data(self.profile)
        enriched_response = self.enrich_all(data, self.profile)
        post_processor = self.profile["post_process"]
        post_process_method = globals()[post_processor]
        post_processed = [post_process_method(data_item) for data_item in enriched_response]
        logger.info(f"Completed processing data for profile {self.profile.get('profile')}")
        return {self.profile["profile"]: post_processed}

    def __fetch_profile_api_data(self, profile):
        """
        Essentially same as the enrich fetch
        TODO: can be combined into one common method.
        """
        api_fetch = profile["fetch"]
        url = api_fetch["url"]
        api_response = self.api_client.get_api_response(url, "pagination_key" in api_fetch,
                                                        api_fetch.get("pagination_key"), **self.profile_inputs)
        data = self.__nested_fetch(api_response, *api_fetch["path"]) if api_fetch["path"] else api_response
        return data

    def __filter_keys(self, source_dict, filters):
        """
        This takes a list of paths as Filters and fills a new Dict and returns it.

        """
        target_dict = {}
        for key_filter in filters:
            if type(key_filter[1]) in SUPPORTED_ENUMS:
                value = key_filter[1].value
            else:
                value = self.__nested_fetch(source_dict, *key_filter[1])
            target_dict[key_filter[0]] = value
        return target_dict

    def enrich_response(self, enrich, response):
        """
        Fetches the required keys from the response and forms the API
        call for the enrichment and returns.
        """
        logger.info(f"Enriching response with {enrich} for profile {self.profile.get('profile')}")
        input_params = self.__filter_keys(response, [(input_key, [input_key]) for input_key in enrich["inputs"]])
        url = enrich["url"]
        api_response = self.api_client.get_api_response(url, False, None, **input_params)
        data = self.__nested_fetch(api_response, *enrich["path"]) if enrich["path"] else api_response
        logger.info(f"Done enriching response with {enrich} for profile {self.profile.get('profile')}")
        filtered_data = self.__filter_keys(data, enrich["filter"])
        ## Add Traces
        filtered_data["_parent"] = response
        filtered_data["_detail"] = api_response
        return filtered_data

    def __merge_both(self, dict1, dict2):
        return {**dict1, **dict2}

    def enrich_all(self, response_list, profile):
        out_data = []
        enrichment_list = profile["enrich_each"]
        for response in response_list:
            filtered_response = self.__filter_keys(response, profile["fetch"]["filter"])
            for enrich in enrichment_list:
                enriched = self.enrich_response(enrich, response)
                filtered_response = self.__merge_both(filtered_response, enriched)
            out_data.append(filtered_response)
        return out_data


class SonarCubeCommunityAPIExtractManager:

    def __init__(self, cmd_args):
        """
        Requires config to have auth_token and base_url
        Requires api_inputs to have Profile specific inputs such as Project, etc.
        """
        self.base_url = cmd_args.base_url
        self.project_key = cmd_args.project_key
        self.user_token = cmd_args.user_token

        self.config = {
            "auth_token": self.user_token,
            "base_url": self.base_url
        }
        self.api_inputs = {
            "project": self.project_key,
            "page": 1,
            "page_size": PAGE_SIZE
        }
        if not {"auth_token", "base_url"}.issubset(set(self.config.keys())):
            raise Exception("Missing required config params auth_token or base URL")

    def get_all_profile_extracts(self):
        """
        Returns the list of JSON keyed by per profile name
        See : ALL_PROFILES list at the top
        """
        api_client = SonarQubeAPIClient(self.config)
        all_profiles = {}
        for profile in ALL_PROFILES:
            profile_obj = SonarProfileExtract(api_client, profile, self.api_inputs)
            all_profiles.update(profile_obj.get_profile_data())
        return all_profiles

    def get_data(self):
        extracts = self.get_all_profile_extracts()
        all_extracts = []
        for profile in extracts:
            all_extracts.extend(extracts[profile])
            logger.info(f"Added {len(extracts[profile])} entries for {profile}")
        return all_extracts


"""
How to run this : See example below
"""

# from collections import namedtuple

# ## Just for the test, actual CMDArgs would come from the CLI
# CmdArgs = namedtuple("CmdArgs", ["project_key", "user_token", "base_url"])
# cmdargs = CmdArgs("rege", "squ_dbd067dc10ab62688a9460cd13cab09b24e5f630", "http://127.0.0.1:9000")
#
# sonar_interface = SonarCubeAPIExtractManager(cmdargs)
# all_extracts = sonar_interface.get_data()
#
# headers = ["Component", "Project", "Type", "SecurityCategory", "Severity", "Line", "Title", "RuleKey", "Date", "Status", "FilePath", "Key", "Description", "Remediation", "Name", "Rule"]
#
# json.dump(all_extracts, open('out.json', 'w'), indent=4)
#
# import csv
# with open("newCSV.csv", 'w', newline='') as csvfile:
#     writer = csv.DictWriter(csvfile, fieldnames=headers)
#     writer.writeheader()
#     writer.writerows(all_extracts)
#