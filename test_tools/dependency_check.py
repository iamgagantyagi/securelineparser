import sys
import logging
import re
import xml.etree.ElementTree as XmlTree
sys.path.append('/root/.pyenv/versions/3.9.17/lib/python3.9/site-packages')
from dateutil import parser
from packageurl import PackageURL
from cpe import CPE

logger = logging.getLogger()


class DependencyCheck:
    mapping_severity = {
        "info": "Info",
        "low": "Low",
        "moderate": "Medium",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }

    def __init__(self, cmd_args):
        self.test = "Dependency Check Scan"
        self.filepath = cmd_args.path

    @staticmethod
    def get_filename_and_path_from_dependency(dependency, related_dependency, namespace):
        try:
            if not related_dependency:
                return dependency.findtext(
                    f"{namespace}fileName"
                ), dependency.findtext(f"{namespace}filePath")
            if related_dependency.findtext(f"{namespace}fileName"):
                return related_dependency.findtext(
                    f"{namespace}fileName"
                ), related_dependency.findtext(f"{namespace}filePath")
            else:
                # without filename, it would be just a duplicate finding, so we have to skip it. filename
                # is only present for related dependencies since v6.0.0
                return None, None
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_filename_and_path_from_dependency() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_filename_and_path_from_dependency() ")

    @staticmethod
    def get_component_name_and_version_from_dependency(dependency, namespace):
        try:
            identifiers_node = dependency.find(namespace + "identifiers")
            if identifiers_node:
                # analyzing identifier from the more generic to
                package_node = identifiers_node.find(".//" + namespace + "package")
                if package_node:
                    pkg_id = package_node.findtext(f"{namespace}id")
                    purl = PackageURL.from_string(pkg_id)
                    purl_parts = purl.to_dict()
                    component_name = (
                        purl_parts["namespace"] + ":"
                        if purl_parts["namespace"]
                        and len(purl_parts["namespace"]) > 0
                        else ""
                    )
                    component_name += (
                        purl_parts["name"]
                        if purl_parts["name"] and len(purl_parts["name"]) > 0
                        else ""
                    )
                    component_name = component_name if component_name else None
                    component_version = (
                        purl_parts["version"]
                        if purl_parts["version"] and len(purl_parts["version"]) > 0
                        else ""
                    )
                    return component_name, component_version

                cpe_node = identifiers_node.find(
                    ".//" + namespace + 'identifier[@type="cpe"]'
                )
                if cpe_node:
                    pkg_id = cpe_node.findtext(f"{namespace}name")
                    cpe = CPE(pkg_id)
                    component_name = (
                        cpe.get_vendor()[0] + ":"
                        if len(cpe.get_vendor()) > 0
                        else ""
                    )
                    component_name += (
                        cpe.get_product()[0] if len(cpe.get_product()) > 0 else ""
                    )
                    component_name = component_name if component_name else None
                    component_version = (
                        cpe.get_version()[0]
                        if len(cpe.get_version()) > 0
                        else None
                    )
                    return component_name, component_version

                maven_node = identifiers_node.find(
                    ".//" + namespace + 'identifier[@type="maven"]'
                )
                if maven_node:
                    maven_parts = maven_node.findtext(f"{namespace}name").split(
                        ":"
                    )

                    if len(maven_parts) == 3:
                        component_name = maven_parts[0] + ":" + maven_parts[1]
                        component_version = maven_parts[2]
                        return component_name, component_version

            return None, None
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_component_name_and_version_from_dependency() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_component_name_and_version_from_dependency() ")

    def get_finding_from_vulnerability(self, date, dependency, related_dependency, vulnerability, test, namespace):
        (dependency_filename, dependency_filepath, ) = self.get_filename_and_path_from_dependency(
            dependency, related_dependency, namespace
        )
        try:
            if dependency_filename is None:
                return None

            tags = []
            name = vulnerability.findtext(f"{namespace}name")
            if vulnerability.find(f"{namespace}cwes"):
                cwe_field = vulnerability.find(f"{namespace}cwes").findtext(
                    f"{namespace}cwe"
                )
            else:
                cwe_field = vulnerability.findtext(f"{namespace}cwe")

            description = vulnerability.findtext(f"{namespace}description")

            source = vulnerability.get("source")
            if source:
                description += "\n**Source:** " + str(source)

            # Need the notes field since this is how the suppression is documented.
            notes = vulnerability.findtext(f".//{namespace}notes")

            vulnerability_id = name[:28]
            if vulnerability_id and not vulnerability_id.startswith("CVE"):
                # for vulnerability sources which have a CVE, it is the start of the 'name'.
                # for other sources, we have to set it to None
                vulnerability_id = None

            # Use CWE-1035 as fallback
            cwe = 1035  # Vulnerable Third Party Component
            if cwe_field:
                m = re.match(r"^(CWE-)?(\d+)", cwe_field)
                if m:
                    cwe = int(m.group(2))

            (component_name, component_version, ) = self.get_component_name_and_version_from_dependency(
                dependency, namespace
            )

            if component_name is None:
                logger.warning(
                    "component_name was None for File: {}, using dependency file name instead.".format(
                        dependency_filename
                    )
                )
                component_name = dependency_filename

            # some changes in v6.0.0 around CVSS version information

            cvssv2_node = vulnerability.find(namespace + "cvssV2")
            cvssv3_node = vulnerability.find(namespace + "cvssV3")
            severity = vulnerability.findtext(f"{namespace}severity")
            if not severity:
                if cvssv3_node is not None:
                    severity = (
                        cvssv3_node.findtext(f"{namespace}baseSeverity")
                        .lower()
                        .capitalize()
                    )
                elif cvssv2_node is not None:
                    severity = (
                        cvssv2_node.findtext(f"{namespace}severity")
                        .lower()
                        .capitalize()
                    )

            # handle if the severity have something not in the mapping
            # default to 'Medium' and produce warnings in logs
            if severity:
                if severity.strip().lower() not in self.mapping_severity:
                    logger.warning(
                        f"Warning: Unknown severity value detected '{severity}'. Bypass to 'Medium' value"
                    )
                    severity = "Medium"
                else:
                    severity = self.mapping_severity[severity.strip().lower()]
            else:
                severity = "Medium"

            references_node = vulnerability.find(namespace + "references")

            if references_node is not None:
                reference_detail = ""
                for reference_node in references_node.findall(
                    namespace + "reference"
                ):
                    ref_source = reference_node.findtext(f"{namespace}source")
                    ref_url = reference_node.findtext(f"{namespace}url")
                    ref_name = reference_node.findtext(f"{namespace}name")
                    if ref_url == ref_name:
                        reference_detail += (
                            f"**Source:** {ref_source}\n" f"**URL:** {ref_url}\n\n"
                        )
                    else:
                        reference_detail += (
                            f"**Source:** {ref_source}\n"
                            f"**URL:** {ref_url}\n"
                            f"**Name:** {ref_name}\n\n"
                        )

            if related_dependency is not None:
                tags.append("related")

            if vulnerability.tag == "{}suppressedVulnerability".format(namespace):
                if notes is None:
                    notes = "Document on why we are suppressing this vulnerability is missing!"
                    tags.append("no_suppression_document")
                remediation = "**This vulnerability is mitigated and/or suppressed:** {}\n".format(
                    notes
                )
                remediation = (
                    remediation
                    + "Update {}:{} to at least the version recommended in the description".format(
                        component_name, component_version
                    )
                )
                tags.append("suppressed")

            else:
                remediation = "Update {}:{} to at least the version recommended in the description".format(
                    component_name, component_version
                )
                description += "\n**Filepath:** " + str(dependency_filepath)

            vulnerability_dict_data = dict()
            vulnerability_dict_data["Date"] = date
            vulnerability_dict_data["CWE/CVE"] = cwe
            vulnerability_dict_data["ToolName"] = test
            vulnerability_dict_data["Severity"] = severity
            vulnerability_dict_data["Title"] = f"{component_name}:{component_version} | {name}"
            vulnerability_dict_data["Remediation"] = remediation
            vulnerability_dict_data["Description"] = description

            logger.debug(f"vulnerability data: {vulnerability_dict_data}")
            return vulnerability_dict_data
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_finding_from_vulnerability() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_finding_from_vulnerability() ")

    def get_data(self):
        try:
            dict_list = list()
            with open(self.filepath, 'r') as file:
                content = file.read()
            logger.info("Read xml file content")
            scan = XmlTree.fromstring(content)
            regex = r"{.*}"
            matches = re.match(regex, scan.tag)
            try:
                namespace = matches.group(0)
            except Exception as e:
                namespace = ""
                logger.info(f"Handled exception and set namespace value to empty {e}")

            dependencies = scan.find(namespace + "dependencies")
            scan_date = None
            if scan.find(f"{namespace}projectInfo"):
                project_info_node = scan.find(f"{namespace}projectInfo")
                if project_info_node.findtext(f"{namespace}reportDate"):
                    scan_date = parser.parse(
                        project_info_node.findtext(f"{namespace}reportDate")
                    )
                logger.info(f"Scan report date : {scan_date.date()}")

            if dependencies:
                for dependency in dependencies.findall(namespace + "dependency"):
                    vulnerability_dict_data = dict()
                    vulnerabilities = dependency.find(
                        namespace + "vulnerabilities"
                    )
                    if vulnerabilities is not None:
                        for vulnerability in vulnerabilities.findall(namespace + "vulnerability"):
                            if scan_date:
                                date = str(scan_date.date())
                            else:
                                date = ""

                            if vulnerability:
                                vulnerability_dict_data = self.get_finding_from_vulnerability(
                                    date,
                                    dependency,
                                    None,
                                    vulnerability,
                                    self.test,
                                    namespace,
                                )

                                related_dependencies = dependency.find(
                                    namespace + "relatedDependencies"
                                )
                                if related_dependencies:
                                    for (relatedDependency) in related_dependencies.findall(
                                        namespace + "relatedDependency"
                                    ):
                                        vulnerability_dict_data = (
                                            self.get_finding_from_vulnerability(
                                                date,
                                                dependency,
                                                relatedDependency,
                                                vulnerability,
                                                self.test,
                                                namespace,
                                            )
                                        )

                    if vulnerability_dict_data != {}:
                        dict_list.append(vulnerability_dict_data)

            logger.debug(f"dict list : {dict_list}")
            return dict_list
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")
