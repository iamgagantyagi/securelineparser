import duckdb
import psycopg2
from datetime import datetime
import logging
from enum import Enum
import os
import json
import hashlib

logger = logging.getLogger()


class Status(Enum):
    INITIATED = "INITIATED"
    QG_FAILED = "QG_FAILED"
    QG_PASSED = "QG_PASSED"
    PARSER_FAILED = "PARSER_FAILED"

class PGConnection:

        def __init__(self, pg_params):
                self.pg_conn_params = {
                        'host': pg_params.get("host"),
                        'port': pg_params.get("port"),
                        'dbname': pg_params.get("dbname"),
                        'user': pg_params.get("user"),
                        'password': pg_params.get("password")
                }
        
        def connect(self):
                pg_conn = psycopg2.connect(**self.pg_conn_params)
                pg_cursor = pg_conn.cursor()

                self.pg_conn = pg_conn
                self.pg_cursor = pg_cursor
                return pg_conn, pg_cursor
        
        def disconnect(self):
                if hasattr(self, 'pg_cursor'):
                        self.pg_cursor.close()
                if hasattr(self, 'pg_conn'):
                        self.pg_conn.close()



class BuildsManager:

        def __init__(self, cmd_args, pg_conn_obj, builds_table_name):
                self.app = cmd_args.app_name if cmd_args.app_name else "Default"
                self.module = cmd_args.module_name if cmd_args.module_name else "Default"
                self.branch = cmd_args.branch_name if cmd_args.branch_name else "Default"
                self.build_number = cmd_args.build_number if cmd_args.build_number else datetime.now().strftime("%Y%m%d%H%M%S") 
                self.tool = cmd_args.test_name
                self.builds_table_name = builds_table_name

                self.pg_conn, self.pg_cursor = pg_conn_obj.connect()
        
        def update_builds(self, build_id, build_status, status_details, remarks = None):

                update_query = """
                WITH update_old_latest AS (
                        UPDATE {builds_table_name}
                        SET is_latest = FALSE
                        WHERE is_latest = TRUE 
                        AND app = %(app)s 
                        AND module = %(module)s
                        AND branch = %(branch)s
                        AND tool = %(tool)s
                )
                UPDATE {builds_table_name}
                SET is_latest = TRUE,
                        updated_at = NOW(),
                        build_status = %(build_status)s,
                        run_remarks = %(remarks)s,
                        status_details = %(status_details)s,
                        tool_build_endtime = NOW()
                WHERE id = %(build_id)s
                """


                item = {
                        "app": self.app,
                        "module": self.module,
                        "branch": self.branch,
                        "build_id": build_id,
                        "tool": self.tool,
                        "build_status": build_status,
                        "remarks": remarks,
                        "status_details": json.dumps(status_details)
                }

                try:
                        self.pg_cursor.execute(update_query.format(builds_table_name=self.builds_table_name), item)
                        self.pg_conn.commit()
                except Exception as e:
                        self.pg_conn.rollback()
                        print("Error:", e)

        def insert_builds(self):


                insert_query = """
                INSERT INTO {builds_table_name}
                        (app, module, branch, build_number, tool, build_status, tool_build_starttime) 
                VALUES 
                        (%(app)s, %(module)s, %(branch)s, %(build_number)s, %(tool)s, %(build_status)s, NOW())
                RETURNING id
                """



                item = {
                        "app": self.app,
                        "module": self.module,
                        "branch": self.branch,
                        "build_number": self.build_number,
                        "tool": self.tool,
                        "build_status": Status.INITIATED.value,
                }

                try:
                        self.pg_cursor.execute(insert_query.format(builds_table_name=self.builds_table_name), item)
                        new_id = self.pg_cursor.fetchone()[0]
                        self.pg_conn.commit()
                        return new_id
                
                except Exception as e:
                        self.pg_conn.rollback()
                        print("Error:", e)
        
        def get_last_successful_build_id(self):
                select_builds_query = f"""
                SELECT MAX(id) AS build_id 
                FROM {self.builds_table_name}
                WHERE (build_status = %s OR build_status = %s)
                AND app = %s
                AND module = %s
                AND tool = %s
                """
                params = (Status.QG_PASSED.value, Status.QG_FAILED.value, self.app, self.module, self.tool)

                
                self.pg_cursor.execute(select_builds_query, params)
                return self.pg_cursor.fetchone()[0]

class FindingsManager:

        def __init__(self, build_id, pg_conn_obj, cmd_args, input_json):
                self.findings_table_name = input_json.get("postgres_findings_table")
                self.local_findings_table_name = "local_findings"

                if cmd_args.module_name:
                        suppression_filename = f"{cmd_args.app_name}_{cmd_args.module_name}_{cmd_args.branch_name}.csv"
                else:
                        suppression_filename = f"{cmd_args.app_name}_{cmd_args.branch_name}.csv"
                
                suppression_filepath = f"{input_json.get('suppression_folder_path')}/{suppression_filename}"
                
                if not os.path.exists(suppression_filepath):
                        logger.info(f"{suppression_filepath} not found. Using default suppression file.")
                        suppression_filename = input_json.get('default_suppression_filename')
                        suppression_filepath = f"{input_json.get('suppression_folder_path')}/{suppression_filename}"
                else:
                        logger.info(f"Using suppression file: {suppression_filepath}")

                self.suppression_filename = suppression_filename
                self.suppression_file_path = suppression_filepath
                self.build_id = build_id
                self.old_findings_table_name = "old_findings"

                self.duckdb_conn = duckdb.connect()

                self.pg_conn, self.pg_cursor = pg_conn_obj.connect()


        def load_findings_into_duckdb(self, dict_data, headers):
                try:
                        all_columns = headers + ["is_new"] + ["suppressed"]
                        create_columns = ", ".join([f'"{col}" VARCHAR' for col in headers] + ['"is_new" BOOLEAN'] + ['"suppressed" BOOLEAN'])
                        self.duckdb_conn.execute(f"CREATE OR REPLACE TABLE {self.local_findings_table_name} ({create_columns});")

                        formatted_data = []
                        for row in dict_data:
                                formatted_row = {key: row.get(key, None) for key in headers}
                                formatted_row["is_new"] = True
                                formatted_row["suppressed"] = False
                                formatted_data.append(tuple(formatted_row.values()))

                        placeholders = ", ".join(["?"] * len(all_columns))
                        insert_query = f"INSERT INTO {self.local_findings_table_name} VALUES ({placeholders})"

                        self.duckdb_conn.executemany(insert_query, formatted_data)

                except Exception as e:
                        print("Error:", e)
        

        def filter_new_findings(self, builds_manager_obj):
                build_id = builds_manager_obj.get_last_successful_build_id()
                if build_id:
                # Fetch old findings from the last successful build
                        select_findings_query = f"""
                                SELECT * FROM {self.findings_table_name}
                                WHERE build_id = %s
                        """
                        self.pg_cursor.execute(select_findings_query, (build_id,))
                        column_names = [desc[0] for desc in self.pg_cursor.description]
                        quoted_column_names = [f'"{col}"' if '-' in col else col for col in column_names]
                        old_findings = self.pg_cursor.fetchall()

                        formatted_old_findings = [
                                tuple(
                                value.strftime('%Y-%m-%d %H:%M:%S') if isinstance(value, datetime)
                                else 'NULL' if value is None
                                else value
                                for value in row
                                )
                                for row in old_findings
                        ]

                        if formatted_old_findings:
                                create_table_query = f"""
                                CREATE OR REPLACE TABLE {self.old_findings_table_name} (
                                        {', '.join([f'{col} VARCHAR' for col in quoted_column_names])}
                                )
                                """
                                self.duckdb_conn.execute(create_table_query)

                                insert_query = f"""
                                INSERT INTO {self.old_findings_table_name} ({', '.join(quoted_column_names)})
                                VALUES ({', '.join(['?' for _ in quoted_column_names])})
                                """
                                self.duckdb_conn.executemany(insert_query, formatted_old_findings)

                                update_query = f"""
                                UPDATE {self.local_findings_table_name} AS lf
                                SET is_new = FALSE
                                FROM {self.old_findings_table_name} AS of
                                WHERE lf."Severity" = of.severity
                                AND lf."Title" = of.title
                                AND lf."Remediation" = of.remediation
                                AND lf."Description" = of.description
                                """
                                self.duckdb_conn.execute(update_query)

        def load_suppressions_into_list(self):
                try:
                        with open(self.suppression_file_path, 'r') as file:
                                suppressions_list = [line.strip() for line in file]

                        return suppressions_list
                except Exception as e:
                        logger.error(f"An unexpected error occurred: {e}")

        def generate_hash(self, item, column_names):
                exclude_list = ["Date", "UniqueKey", "IsNew", "Suppressed", "BuildID"]
                eligible_keys = [key for key in column_names if key not in exclude_list]
                concatenated_values = ''.join(str(item.get(key, "")) for key in eligible_keys)

                # Generate the MD5 hash
                md5_hash = hashlib.md5(concatenated_values.encode("utf-8")).hexdigest()
                return md5_hash
        
        def check_cwe_cve_suppression(self, cwe_cve, suppressions_list):
                if ', ' in cwe_cve:
                        cve, cwes = cwe_cve.split(', ', 1)
                        cwes = eval(cwes)
                else:
                        cve = cwe_cve
                        cwes = []


                if cve in suppressions_list:
                        return True
                for cwe in cwes:
                        if cwe in suppressions_list:
                                return True
                return False
        
        def insert_findings(self, dict_data, headers, builds_manager_obj):
                self.load_findings_into_duckdb(dict_data, headers)
                suppressions_list = self.load_suppressions_into_list()
                self.filter_new_findings(builds_manager_obj)
                processed_findings = self.duckdb_conn.execute(f"SELECT * FROM {self.local_findings_table_name}").fetchall()
                column_names = ["Date", "CWE/CVE", "ToolName", "Severity", "Title", "Description", "Remediation", "SystemInfo",
                                "Component", "Project", "Type", "SecurityCategory", "Line", "Status", "FilePath", "Key",
                                "Name", "Rule", "Trace", "Kind", "Namespace", "CIS_Control", "IsNew", "Suppressed", "BuildID", "UniqueKey"
                                ]


                insert_query = """
                        INSERT INTO findings (
                                "cwe-cve", toolname, severity, title, description, remediation, systeminfo,
                                component, project, type, securitycategory, line, status, filepath, key,
                                name, rule, trace, kind, namespace, cis_control, is_new, suppressed, build_id, unique_key
                        ) VALUES (
                                %(CWE/CVE)s, %(ToolName)s, %(Severity)s, %(Title)s, %(Description)s, %(Remediation)s, %(SystemInfo)s,
                                %(Component)s, %(Project)s, %(Type)s, %(SecurityCategory)s, %(Line)s, %(Status)s, %(FilePath)s, %(Key)s,
                                %(Name)s, %(Rule)s, %(Trace)s, %(Kind)s, %(Namespace)s, %(CIS_Control)s, %(IsNew)s, %(Suppressed)s, %(BuildID)s,  %(UniqueKey)s
                        )
                        """


                for row in processed_findings:
                        item = {col: value for col, value in zip(column_names, row)}
                        item = {key: item.get(key, None) for key in column_names}
                        item["BuildID"] = self.build_id
                        item["UniqueKey"] = self.generate_hash(item, column_names)
                        if item["UniqueKey"] in suppressions_list:
                                item["Suppressed"] = True
                        # if item["ToolName"] in ["Trivy Image Scan", "ZapScan", "Trufflehog3 Scan", "Dependency Check Scan", "OpenVAS", "sonarqube"]:
                        #         item["Suppressed"] = self.check_cwe_cve_suppression(item["CWE/CVE"], suppressions_list)
                        self.pg_cursor.execute(insert_query, item)

                try:
                        self.pg_conn.commit()
                        return self.suppression_filename
                except Exception as e:
                        self.pg_conn.rollback()
                        print("Error:", e)
                finally:
                        self.close_duckdb()
        
        def check_quality_gate(self, query):
                self.pg_cursor.execute(query.format(table_name=self.findings_table_name, build_id=self.build_id))
                return self.pg_cursor.fetchone()[0]


        def close_duckdb(self):
                self.duckdb_conn.close()


class CIS_Controls_Mappings:
        def __init__(self, pg_conn_obj, cis_controls_table_name):
                self.pg_conn, self.pg_cursor = pg_conn_obj.connect()
                self.cis_controls_table_name = cis_controls_table_name
        
        def fetch_cis_controls(self):
                self.pg_cursor.execute(f"SELECT * FROM {self.cis_controls_table_name}")
                data = self.pg_cursor.fetchall()
                result = {row[1]: row[3] for row in data}
                return result