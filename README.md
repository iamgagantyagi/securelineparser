# security tools parser 
This tool will parse the output of security tools and transform it into json/csv. 
The output json/csv could further be used for importing into other test/defect management tools (Ex -> Jira)

## Prerequisite:
1. Install Python3.7 or above, pip and java (openjdk 11.0.17)
2. Install dependency packages by running below command:
    $ pip3 install -r requirements.txt

## Some examples of security tools supported are:
1. TruffleHog3 scan
2. Zap Scan
3. Dependency checker
4. Sonarqube

Below is the high level structure of this tool and its related files location. 

- security_tools_parser 
  - lib
    - logger.py
    - security_tools_parser.py
  - test_tools
    - cis_audit.py
    - dependency_check.py
    - kubescape_scanning.py
    - sonarqube.py
    - trivy.py
    - truffle_hog3.py
    - zap_scan.py
  - README.md
  - run_parser.py
  - config.json
  - requirements.txt
  			

In addition to this, we will create logs and output_files folder in security_tools_parser folder and 
add output csv/json and log file at the runtime.

To add any new tool, we need to add parser in <tool_name>.py format in test_tools directory 
and add condition in run_parser method to execute based on commandline input.

config.json file have configurable params like:
	csv_headers
	cwe_url
	log_filename
	log_level

You can use below steps to run this tool:
-----------------
1. Open cmd prompt/console
2. Go to security_tools_parser directory. 
3. Create PostgreSQL Instance with Podman/Docker or any cloud service.
4. Create Database in PostgreSQL.
6. Use SQL File to Create Tables.
8. Run the insert_excel python file.
9. Run the tool
cmd> python3 run_parser.py -t <test> -p <test_output_file>

(run above command by replacing the parameters(i.e. base_url,project_key,project_branch,user_auth_key) with your actual parameters value)

python3 run_parser.py -t "Trufflehog3 Scan" -p "D:\DevSecOps\truffelhog_output.json" -m module_name -A app_name -B branch_name -bn build_number
(module, app_name, branch_name and build_number are optional in the above command)

Example:
-----------------
Run below command to run the script and generate json output:

CI Tools:

1) Trufflehog - Secret Scan
cmd> python3 run_parser.py -t "Trufflehog3 Scan" -p "D:\DevSecOps\truffelhog_output.json" 

2) Dependency Check - Software Composition Analysis (SCA)
cmd> python3 run_parser.py -t "Dependency Check Scan" -p "D:\DevSecOps\dependency-check-report.xml"

3) SonarQube - Static Application Security Testing (SAST)
-  We have Sonarqube edition - Community and Developer
cmd> python3 run_parser.py -t "sonarqube" -u base_url -k project_key -B project_branch -a user_auth_key

4) Trivy dockerfile - Container Misconfig Scan
cmd> python3 run_parser.py -t "TrivyMisconfig" -p "D:\DevSecOps\Trivy_Misconfig_result.json"

5) Trivy container scan - Container Image Vulnerability Scan
cmd> python3 run_parser.py -t "Trivy scan" -p "D:\DevSecOps\Trivy_result.json" 

6) Trivy CIS scan - CIS Compliance Scan for docker images 
cmd> python3 run_parser.py -t "Trivy CIS scan" -p "D:\DevSecOps\Trivy_CIS_result.json"

7) Kubescape -> Static_Kubernetes Security Scan (Infra code)
cmd> python3 run_parser.py -t "Kubescape Scanning_CI" -p "D:\DevSecOps\Kubescape\CI_results.xml"     

8) Andriod Security Assesment -> APK static security audit 
cmd> python3 run_parser.py -t "android mobile scan" -p "D:\DevSecOps\SAST-AppSec-1.json"

9) iOS Security Assesment -> IPA static security audit
cmd> python3 run_parser.py -t "ios mobile scan" -p "D:\DevSecOps\SAST-AppSec-2.json"


CD Tools:

10) OWASP ZAP - Dynamic Application Security Testing (DAST)
cmd> python3 run_parser.py -t "ZAP Scan" -p "D:\DevSecOps\zap_report"

11) Kubescape -> Dynamic_Kubernetes Security Scan
cmd> python3 run_parser.py -t "Kubescape Scanning_CD" -p "D:\DevSecOps\Kubescape\CD_results.xml" 

12) CIS Ansible -> OS_CIS_Compliance Scan
cmd> python3 run_parser.py -t "UBUNTU20-CIS-Audit" -p "D:\DevSecOps\cis_audit_UBUNTU2004.json" 

13) Cloud Security Suite -> Cloud Security Audit
cmd> python3 run_parser.py -t "CSS scan" -p "D:\DevSecOps\cloud_result.json"

14) Prowler AWS -> Cloud Security Audit
cmd> python3 run_parser.py -t "AWS Cloud Security Suite" -p "D:\DevSecOps\aws_cloud_result.json"

15) Prowler Azure -> Cloud Security Audit
cmd> python3 run_parser.py -t "Azure Cloud Security Suite" -p "D:\DevSecOps\azure_cloud_result.json"

16) OpenVas -> Cloud Security Audit
cmd> python3 run_parser.py -t "Host Vulnerability Assessment" -p "D:\DevSecOps\openvas_vulnerbility.xml"
