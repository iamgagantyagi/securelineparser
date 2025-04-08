import json
import logging
import os
import platform
from argparse import ArgumentParser

logger = logging.getLogger()

def parse_arguments():
    try:
        description = "This script transforms data received from tool to csv format."
        epilog = "Provides help for the commandline options"
        parser = ArgumentParser(description=description, epilog=epilog)
        parser.add_argument('-t', '--test_name', action='store', help='provide the test name')
        parser.add_argument('-p', '--path', action='store', help='provide the path for test output file')
        parser.add_argument('-o', '--output', action='store', default='consolidated_test_output.json',
                            help='creates csv/json from the test output file')
        parser.add_argument('-u','--base_url', type=str, help='provide the base URL of sonarcube')
        parser.add_argument('-k','--project_key', type=str, help='provide the project key')
        parser.add_argument('-b','--project_branch', type=str, help='provide the project branch name ')
        parser.add_argument('-a','--user_token', type=str, help='provide the authentication token')
        parser.add_argument('-m', '--module_name', action='store', help='provide the module name')
        parser.add_argument('-A', '--app_name', action='store', help='provide the application name')
        parser.add_argument('-B', '--branch_name', action='store', help='provide the branch name')
        parser.add_argument('-bn','--build_number', action='store', help='provide the build number')


        cmd_args = parser.parse_args()
        logger.info(f"Arguments parsed successfully : {cmd_args}")
        return cmd_args
    except Exception as e:
        logger.fatal(f"Arguments are not correctly provided. : {e}")
        raise Exception("Arguments are not correctly provided.")


def store_data_into_database(dict_data, cmd_args, input_json, builds_manager, findings_manager):

    try:
        system_name = platform.node()
        if "trivy cis scan" == cmd_args.test_name.lower():
            
            json_file_name = os.path.split(cmd_args.path)[1]
            # Get the ip and system details from json file
            sys_details = json_file_name.split("-")
            system_name = sys_details[2] + "-" + sys_details[1]
            logger.info(f"system name details in format os name and IP : {system_name}")

        elif "cis" in cmd_args.test_name.lower() and cmd_args.test_name.lower() != 'awscisaudit':
            json_file_name = os.path.split(cmd_args.path)[1]
            # Get the ip and system details from json file
            sys_details = json_file_name.split("_")
            system_name = sys_details[2] + "_" + sys_details[1]
            logger.info(f"system name details in format os name and IP : {system_name}")

        if ("kubescape" not in cmd_args.test_name.lower()):
            for each in dict_data:
                each['SystemInfo'] = system_name
        headers = input_json['csv_headers'] + input_json['kubescape_headers'] + input_json['cis_headers']
        suppression_filename = findings_manager.insert_findings(dict_data, headers, builds_manager)
        return suppression_filename
    except Exception as e:
        logger.fatal(f"Failed to store data into database : {e}")
        raise Exception("Failed to store data into database")
    
def check_quality_gate(cmd_args, findings_manager, input_json):
    try:
        if cmd_args.module_name:
            quality_gate_filename = f"{cmd_args.app_name}_{cmd_args.module_name}_{cmd_args.branch_name}.json"
        else:
            quality_gate_filename = f"{cmd_args.app_name}_{cmd_args.branch_name}.json"
        
        quality_gate_filepath = f"{input_json.get('quality_gate_folder_path')}/{quality_gate_filename}"

        if not os.path.exists(quality_gate_filepath):
            logger.info(f"{quality_gate_filepath} not found. Using default quality gate file.")
            quality_gate_filename = input_json.get('default_quality_gate_filename')
            quality_gate_filepath = f"{input_json.get('quality_gate_folder_path')}/{quality_gate_filename}"

        with open(quality_gate_filepath) as f:
            quality_gate = json.load(f)
            quality_gate_query = quality_gate.get("quality_gate_query")
            quality_gate_result = findings_manager.check_quality_gate(quality_gate_query)
            return quality_gate_result, quality_gate_filename
        
    except Exception as e:
        logger.fatal(f"Failed to check quality gate : {e}")
        raise Exception("Failed to check quality gate")