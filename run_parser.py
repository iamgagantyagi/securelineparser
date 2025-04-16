import json
import logging
import os
import platform

from lib.security_tools_parser import parse_arguments, store_data_into_database, check_quality_gate
from lib.logger import Log
from lib.db_utils import PGConnection, BuildsManager, FindingsManager, Status
from test_tools.truffle_hog3 import TruffleHog3
from test_tools.zap_scan import ZapScan
from test_tools.dependency_check import DependencyCheck
from test_tools.cis_audit import CISAudit
from test_tools.kubescape_scanning import KubeScape
from test_tools.trivy import Trivy
from test_tools.trivy_cis import Trivy_CIS
from test_tools.trivy_misconfig import Trivy_MisConfig
from test_tools.sonarqube import Sonarqube
from test_tools.sonar_extractor_community import SonarCubeCommunityAPIExtractManager
from test_tools.sonar_extractor_developer import SonarCubeDeveloperAPIExtractManager
from test_tools.css import CloudSecuritySuite
from test_tools.android_mobile_scanning import Android_Mobile_Scanning
from test_tools.ios_mobile_scanning import IOS_Mobile_Scanning
from test_tools.prowler_aws import Prowler_AWS
from test_tools.prowler_azure import Prowler_Azure
from test_tools.openvas import OpenVas

def run_parser(command_args, pg_connection, input_json):
    try:
        # Convert and replace test output filename with titlecase
        parser_class = command_args.test_name.title().replace(" ", "")
        logging.info(f"Tool parser class to run : {parser_class}")

        # Create an object of tool parser class
        parser_scan_output = None

        if parser_class.lower() == "zapscan":
            parser_scan_output = ZapScan(command_args)
        elif parser_class.lower() == "trufflehog3scan":
            parser_scan_output = TruffleHog3(command_args)
        elif parser_class.lower() == "dependencycheckscan":
            parser_scan_output = DependencyCheck(command_args)
        elif "cis-audit" in parser_class.lower():
            parser_scan_output = CISAudit(command_args, pg_connection, input_json)
        elif "kubescape" in parser_class.lower():
            parser_scan_output = KubeScape(command_args)
        elif "trivycis" in parser_class.lower():
            parser_scan_output = Trivy_CIS(command_args)
        elif "trivymisconfig" in parser_class.lower():
            parser_scan_output = Trivy_MisConfig(command_args)
        elif "trivy" in parser_class.lower():
            parser_scan_output = Trivy(command_args)
        elif "sonarqube" in parser_class.lower():
            #parser_scan_output = Sonarqube(command_args)
            if input_json.get("sonarqube_edition").lower() == "community":
                parser_scan_output = SonarCubeCommunityAPIExtractManager(command_args)
            else:
                parser_scan_output = SonarCubeDeveloperAPIExtractManager(command_args)
        elif "css" in parser_class.lower():
            parser_scan_output = CloudSecuritySuite(command_args)
        elif "android" in parser_class.lower():
            parser_scan_output = Android_Mobile_Scanning(command_args)
        elif "ios" in parser_class.lower():
            parser_scan_output = IOS_Mobile_Scanning(command_args)
        elif "awscloudsecuritysuite" in parser_class.lower():
            parser_scan_output = Prowler_AWS(command_args)
        elif "azurecloudsecuritysuite" in parser_class.lower():
            parser_scan_output = Prowler_Azure(command_args)
        elif "hostvulnerabilityassessment" in parser_class.lower():
            parser_scan_output = OpenVas(command_args)
        else:
            logging.fatal("No tool specified. Please provide correct arguments.")
            raise Exception("No tool specified. Please provide correct arguments.")

        # get data from test tool parser and convert to csv
        get_dict_data = parser_scan_output.get_data()
        logging.info("run_parser completed successfully.")
        return get_dict_data

    except Exception as e:
        logging.fatal(f"Exception occurred in run_parser : {e}")
        raise Exception(f"Exception occurred in run_parser ")


def configure_logger(input_file):
    # Create logs folder if not already present in a4mation directory
    log_path = "logs"
    if not os.path.exists(log_path):
        os.mkdir(log_path)
    log_filename = log_path + os.sep + input_file["log_filename"]

    logger = Log()

    if input_json["log_level"].lower() == "info":
        logger.logfile(log_filename, log_level=logging.INFO)
    else:
        logger.logfile(log_filename, log_level=logging.DEBUG)

    logging.info(f"logging level set to {input_file['log_level']}")
    logging.info(f"logger file path and name : {log_filename}")


if __name__ == "__main__":
    # Load input json file
    json_input_filepath = "config.json"
    with open(json_input_filepath, 'r') as json_file:
        input_json = json.load(json_file)

    configure_logger(input_json)

    # Parse command line arguments
    cmd_args = parse_arguments()

    logging.info(f"System name : {platform.node()}")
    logging.info(f"Tool name : {cmd_args.test_name}")
    logging.info(f"Input file json or xml : {cmd_args.path}")

    pg_connection = PGConnection(input_json.get("pg_conn_params"))

    builds_manager = BuildsManager(cmd_args, pg_connection, input_json.get("postgres_builds_table"))
    build_id = builds_manager.insert_builds()
    logging.info(f"Build id : {build_id}")
    run_remarks = None
    quality_gate_result = True
    quality_gate_filename = input_json.get('default_quality_gate_filename')
    suppression_filename = input_json.get('default_suppression_filename')
    try:
    # Parse the data and create csv
        get_dict_data_from_parser = run_parser(cmd_args, pg_connection, input_json)
        # logging.info(get_dict_data_from_parser)
        if get_dict_data_from_parser:

            findings_manager = FindingsManager(build_id, pg_connection, cmd_args, input_json)      
            suppression_filename = store_data_into_database(get_dict_data_from_parser, cmd_args, input_json, builds_manager,findings_manager)
            
            quality_gate_result, quality_gate_filename = check_quality_gate(cmd_args, findings_manager, input_json)
            logging.info(f"Quality gate result : {quality_gate_result}")
        
        else:
            run_remarks = "No vulnerabilities found"
            logging.info("No vulnerabilities found")

        status_details = {
            "quality_gate_filename" : quality_gate_filename,
            "suppression_filename" : suppression_filename
        }    

        if quality_gate_result:
            builds_manager.update_builds(build_id, Status.QG_PASSED.value, status_details, run_remarks)
        else:
            builds_manager.update_builds(build_id, Status.QG_FAILED.value, status_details, run_remarks)

    except Exception as e:
        logging.fatal(f"Error occurred : {e}")
        builds_manager.update_builds(build_id, Status.PARSER_FAILED.value, run_remarks)

    finally:
        pg_connection.disconnect()
