import csv
import json
import logging
import os
import platform
import shutil
from argparse import ArgumentParser
import datetime
import sys
from os.path import dirname, abspath
from pathlib import Path

sys.path.insert(0, dirname(dirname(abspath(__file__)))) # Add root folder to path
sys.path.insert(0, dirname(abspath(__file__))) # Add lab folder to path

from lib.constants import latest_report_folder, output_folder_path, stale_report_folder

import pandas as pd


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
        parser.add_argument('-m', '--module_name', action='store', default='module_name',
                            help='provide the module name')
        parser.add_argument('-A', '--app_name', action='store', default='application_name',
                            help='provide the application name')
        parser.add_argument('-B', '--branch_name', action='store', default='branch_name',
                            help='provide the branch name')


        cmd_args = parser.parse_args()
        logger.info(f"Arguments parsed successfully : {cmd_args}")
        return cmd_args
    except Exception as e:
        logger.fatal(f"Arguments are not correctly provided. : {e}")
        raise Exception("Arguments are not correctly provided.")


def check_header(filename):
    try:
        with open(filename) as f:
            first = f.read(1)
            return first not in '.-0123456789'
    except Exception as e:
        logger.fatal(f"Exception occurred in check_header : {e}")
        raise Exception(f"Exception occurred in check_header ")


def get_output_filename(filename):
    try:
        # Create folder output_files if not already present in a4mation directory
        output_files_path = "output_files"
        if not os.path.exists(output_files_path):
            os.mkdir(output_files_path)

        # Create test tool output file with system name in prefix
        file_path = os.path.join(output_files_path, filename)
        logger.debug(f"output filepath : {file_path}")
        return file_path
    except Exception as e:
        logger.fatal(f"Exception occurred in get_output_filename : {e}")
        raise Exception(f"Exception occurred in get_output_filename ")


def write_to_csv(dict_data, cmd_args, input_json):
    try:
        # Create folder output_files if not already present and get log filename having system name in prefix
        file_path = get_output_filename(cmd_args.output)
        system_name = platform.node()

        if "cis" in cmd_args.test_name.lower() and cmd_args.test_name.lower() != 'awscisaudit':
            json_file_name = os.path.split(cmd_args.path)[1]

            # Get the ip and system details from json file
            sys_details = json_file_name.split("_")
            system_name = sys_details[2] + "_" + sys_details[1]
            logger.info(f"system name details in format os name and IP : {system_name}")

        if ("kubescape" not in cmd_args.test_name.lower()) and ("trivy" not in cmd_args.test_name.lower()):
            for each in dict_data:
                each['SystemInfo'] = system_name
        logger.info(dict_data)
        with open(file_path, 'a+', newline='') as csvfile:
            headers = check_header(file_path)
            if "kubescape" in cmd_args.test_name.lower():
                input_json["csv_headers"].extend(input_json["kubescape_headers"])
            writer = csv.DictWriter(csvfile, fieldnames=input_json['csv_headers'])
            if not headers:
                writer.writeheader()
            writer.writerows(dict_data)
        logger.info("Dictionary data successfully written to csv")
    except Exception as e:
        logger.fatal(f"Failed to write to csv file : {e}")
        raise Exception("Failed to write to csv file")


def add_data_to_json_file(dict_data, json_file):
    try:
        # Create folder output_files if not already present and get log filename having system name in prefix
        file_path = get_output_filename(json_file)

        if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
            logger.info("json file exists and is readable")
            with open(file_path, 'r+') as outfile:
                # First we load existing data into a dict.
                file_data = json.load(outfile)
                # Join new_data with file_data inside emp_details
                logger.debug(f"Write to json : {file_data}")
                file_data.extend(dict_data)
                # Sets file's current position at offset.
                outfile.seek(0)
                # convert back to json.
                json.dump(file_data, outfile, indent=4)
        else:
            with open(file_path, 'w') as outfile:
                json.dump(dict_data, outfile)
        logger.info("Dictionary data successfully written to transformed json file")
    except Exception as e:
        logger.fatal(f"Failed to write/append to json file : {e}")
        raise Exception("Failed to write/append to json file")


def write_to_json(dict_data, cmd_args):
    try:
        # Create/append json file for individual test
        system_name = platform.node()

        if "cis" in cmd_args.test_name.lower() and cmd_args.test_name.lower() != 'aws cis audit':
            # Get the json file name from file path
            json_file_name = os.path.split(cmd_args.path)[1]
            scan_test_filename = "transformed_" + json_file_name
            logger.info(f"Write to transformed json file : {scan_test_filename}")

            # Get the ip and system details from json file
            sys_details = json_file_name.split("_")
            system_name = sys_details[2] + "_" + sys_details[1]
            logger.info(f"system name details in format os name and IP : {system_name}")

        else:
            scan_test_filename = platform.node() + "_" + cmd_args.test_name.title().replace(" ", "") + ".json"
        add_data_to_json_file(dict_data, scan_test_filename)

        # Create/append json file for all test
        if ("kubescape" not in cmd_args.test_name.lower()) and ("trivy" not in cmd_args.test_name.lower()):
            for each in dict_data:
                each['SystemInfo'] = system_name
        add_data_to_json_file(dict_data, cmd_args.output)

    except Exception as e:
        logger.fatal(f"Failed to write to json file : {e}")
        raise Exception("Failed to write to json file")

def move_and_rename_file(src_path, dest_dir, new_filename):
    # Ensure the destination directory exists
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    # Construct the full destination path
    dest_path = os.path.join(dest_dir, new_filename)

    # Move and rename the file
    shutil.move(src_path, dest_path)
    print(f"File moved and renamed to {dest_path}")
    
def generate_test_output_with_new_alert_signal(consolidate_test_output_file_name):
    """
	Logic:
	- Check if 'consolidated_test_output.csv' exists in the output_files folder.
	- If 'consolidated_test_output.csv' exists:
		- Check if 'test_op_with_new_alert_signals.csv' file exists in 'latest_report' folder. Also check if 'latest_report' folder exists.
			- If it does not exist that means it's a first run.
				- In this case, we just add a new column called 'new_alert_signal' in data of 'consolidated_test_output.csv' and store it in 'latest_report' folder. Make sure to recursively create folder as well.
			- If it exists that means this is not a first run.
				- In this case, create a copy (historical data) of 'test_op_with_new_alert_signals.csv' in 'stale_report' folder. Add timestamp in the file_name.
				- Now for any new entry in 'consolidated_test_output.csv', mark 'new_alert_signal' as 'yes'.
				For all existing entries, mark 'new_alert_signal' as 'no'.
	- If consolidated_test_output.csv does not exist:
		- Throw error
	"""
    
    test_output_with_new_alert_signal_file_name = 'test_op_with_new_alert_signal.csv'
    consolidated_test_output_file_path = output_folder_path / consolidate_test_output_file_name
    
    latest_report_file = latest_report_folder / test_output_with_new_alert_signal_file_name
    latest_report_file_1 = latest_report_folder / consolidate_test_output_file_name
    
    if consolidated_test_output_file_path.exists():
        consolidated_df = pd.read_csv(consolidated_test_output_file_path)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Check if latest_report folder and file exist
        if not latest_report_file.exists():
            # First run
            consolidated_df['new_alert_signal'] = 'yes'
            
            # Create latest_report folder if it doesn't exist
            latest_report_folder.mkdir(parents=True, exist_ok=True)
            
            # Save the file
            consolidated_df.to_csv(latest_report_file, index=False)
            consolidated_df.to_csv(latest_report_file_1, index=False)
            logging.info(
                f"First run completed. Latest report file saved in location: {str(latest_report_file.absolute())}")
        else:
            # Not a first run
            # Create a copy in stale_report folder with timestamp
            stale_report_folder.mkdir(parents=True, exist_ok=True)
            stale_file = stale_report_folder / f"test_op_with_new_alert_signals_{timestamp}.csv"
            stale_test_op_df = pd.read_csv(latest_report_file)
            stale_test_op_df.to_csv(stale_file, index=False)
            
            # Now compare the consolidated_df and stale_test_op_df. For any new alert, mark 'new_alert_signal' as no otherwise 'yes'
            consolidated_df_without_date = consolidated_df.drop(['Date'], axis=1)
            stale_test_op_df_without_date = stale_test_op_df.drop(['Date'], axis=1)
            existing_alert_mask = consolidated_df_without_date.apply(tuple, 1).isin(
                stale_test_op_df_without_date.iloc[:, :-1].apply(tuple, 1))
            consolidated_df.loc[existing_alert_mask, 'new_alert_signal'] = 'no'
            
            consolidated_df['new_alert_signal'] = consolidated_df['new_alert_signal'].fillna('yes')
            
            consolidated_df.to_csv(latest_report_file, index=False)
            logging.info(f"Latest report file with new alert notifier saved in : {str(latest_report_file.absolute())}")
            
            consolidated_df.to_csv(latest_report_file_1, index=False)
            logging.info(
                f"Latest report file with new alert notifier saved in : {str(latest_report_file_1.absolute())}")
            
        # Move the stale consolidate_test_output_file_name to stale folder
        consolidate_test_output_file_name_with_timestamp = Path(consolidate_test_output_file_name).stem + timestamp + Path(consolidate_test_output_file_name).suffix
        move_and_rename_file(consolidated_test_output_file_path, stale_report_folder, consolidate_test_output_file_name_with_timestamp)
        
    else:
        raise FileNotFoundError(f"{str(consolidated_test_output_file_path.absolute())} does not exist.")


def create_result_summary_json(app, module, branch, tool, outfile):
    sev_list = []
    cnt = 0
    with open(latest_report_folder / outfile, mode ='r')as file:
        csvFile = csv.reader(file)
        for line in csvFile:
            if cnt == 0:
                cnt += 1
            elif (line[3].title() not in [ x['severity_level'] for x in sev_list ]):
                sev_list.append({"severity_level": line[3].title(), "count": 1})
            else:
                for sev in sev_list:
                    if line[3].title() == sev['severity_level']:
                        sev['count'] += 1

    final_json = { "application_name": app, "module_name": module, 
                    "branch_name": branch, "tool_name": tool, 
                    "severity": sev_list }

    result_summary_filepath = str(latest_report_folder) + '/' + (tool.replace(' ', '_')).lower() + "_result_summary.json"
    with open(result_summary_filepath, 'a+') as jsonfile:
        jsonfile.write(json.dumps(final_json))

