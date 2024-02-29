"""
This Python module is designed to automate the management of service-related information and 
security scan results within a MySQL database. It facilitates the connection to the database
and insertion or updating of service and scan data. 

Key functionalities include:

- Establishing connections to a MySQL database using provided credentials.
- Managing service records, including creating new records with standard attributes 
  and updating existing ones.
- Fetching and executing SQL queries for data manipulation and retrieval.
- Processing Git information to tie services and scan results to 
  specific code commits and branches.
- Reading and analyzing security scan results from JSON files, 
  particularly focusing on Elixir projects.
- Automatically handling version information extracted from Elixir's mix.exs files.

Intended for use in continuous integration/continuous deployment pipelines, 
this script supports automated security monitoring and compliance tracking for 
software services developed in Elixir. It assumes a predefined database schema and 
is configured through environment variables and command-line arguments.

Requirements:
- Python 3.x
- mysql-connector-python package
- Access to a MySQL database
- Environment variables for database credentials and Git information

Usage:
The script is executed with a service name as a command-line argument. 
It assumes the presence of a 'deps_audit.json' file containing security scan results 
and a 'mix.exs' file for Elixir version information in the specified directory path.

Example:
    python security_dashboard_agent.py <service_name>
"""


import json
import os
import sys
import re
import subprocess
from datetime import datetime
import mysql.connector
from mysql.connector import Error


def create_connection(host_name, user_name, user_password, db_name):
    """
    Establishes a connection to a MySQL database.

    Parameters:
    - host_name (str): Database host name.
    - user_name (str): Database user name.
    - user_password (str): Database user password.
    - db_name (str): Database name.

    Returns:
    - connection: MySQL connection object if successful, None otherwise.
    """
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            port=3306,
            user=user_name,
            passwd=user_password,
            database=db_name
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")
    return connection


def execute_query(connection, query, params=None):
    """
    Executes a SQL query against the database.

    Parameters:
    - connection: MySQL connection object.
    - query (str): SQL query to execute.
    - params (tuple, optional): Parameters to use with the query.

    Returns:
    - None
    """
    cursor = connection.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        connection.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
    finally:
        cursor.close()


def fetch_query(connection, query, params=None):
    """
    Fetches the first row of results from a SQL query.

    Parameters:
    - connection: MySQL connection object.
    - query (str): SQL query to execute.
    - params (tuple, optional): Parameters to use with the query.

    Returns:
    - result: The first row of results, or None if no result is found or an error occurs.
    """
    cursor = connection.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        result = cursor.fetchone()
        return result
    except Error as e:
        print(f"The error '{e}' occurred")
        return None
    finally:
        cursor.close()


def check_and_create_service(connection, repo_name, aws_name):
    """
    Checks if a service exists and creates a new service record if not, 
    using standard values for certain fields.

    Parameters:
    - connection: MySQL connection object.
    - repo_name (str): Repository name of the service.

    Returns:
    - None
    """
    check_query = "SELECT * FROM services WHERE RepoName = %s"
    service_exists = fetch_query(connection, check_query, (repo_name,))

    if service_exists:
        print("Service already exists in the database.")
    else:
        command = "git remote show origin | grep 'HEAD branch' | cut -d' ' -f5"
        result = subprocess.run(command, shell=True,
                                text=True, capture_output=True, check=False)
        aws_instance_name = aws_name
        prod_branch_name = result.stdout.strip()
        preprod_branch_name = "preprod"

        insert_query = """
            INSERT INTO services (RepoName, AWSInstanceName, ProdBranchName, PreprodBranchName)
            VALUES (%s, %s, %s, %s)
        """
        execute_query(connection, insert_query, (repo_name,
                      aws_instance_name, prod_branch_name, preprod_branch_name))
        print("New service created successfully.")


def update_service_branch_sha(connection, repo_name, branch_name, new_sha):
    """
    Updates the SHA for a branch of a service.

    Parameters:
    - connection: MySQL connection object.
    - repo_name (str): Repository name of the service.
    - branch_name (str): The name of the branch to update.
    - new_sha (str): The new SHA value for the branch.

    Returns:
    - None
    """
    fetch_branch_names_query = """
    SELECT ProdBranchName, PreprodBranchName FROM services WHERE RepoName = %s
    """
    branch_names = fetch_query(
        connection, fetch_branch_names_query, (repo_name,))
    if branch_names:
        prod_branch_name, preprod_branch_name = branch_names
        if branch_name == prod_branch_name:
            query = "UPDATE services SET ProdBranchSHA = %s WHERE RepoName = %s"
        elif branch_name == preprod_branch_name:
            query = "UPDATE services SET PreprodBranchSHA = %s WHERE RepoName = %s"
        else:
            print("Invalid branch name specified.")
            return
        execute_query(connection, query, (new_sha, repo_name))
    else:
        print("Service with specified repo name not found.")


def insert_or_update_scan_results(connection, service_name, scan_data):
    """
    Inserts or updates scan results for a service.

    Parameters:
    - connection: MySQL connection object.
    - service_name (str): Name of the service.
    - scan_data (dict): Scan data to insert or update.

    Returns:
    - None
    """
    check_query = "SELECT * FROM scans WHERE service_name = %s AND commit_sha = %s"
    existing_entry = fetch_query(
        connection, check_query, (service_name, scan_data['CommitSHA']))

    if existing_entry:
        update_parts = []
        update_values = []
        fields_to_exclude = ['CommitSHA', 'DateOfCommit']
        for key, value in scan_data.items():
            if key not in fields_to_exclude and value is not None:
                update_parts.append(f"{key} = %s")
                update_values.append(value)
        if update_parts:
            update_query = f"UPDATE scans SET {', '.join(update_parts)} WHERE service_name = %s AND commit_sha = %s"
            update_values.append(service_name)
            update_values.append(scan_data['CommitSHA'])
            execute_query(connection, update_query, tuple(update_values))
        else:
            print("No new information to update.")
    else:
        filtered_scan_data = {k: v for k,
                              v in scan_data.items() if v is not None}
        columns = ", ".join(["service_name"] + list(filtered_scan_data.keys()))
        placeholders = ", ".join(["%s"] * len(filtered_scan_data))
        insert_query = f"INSERT INTO scans ({columns}) VALUES ({placeholders})"
        execute_query(connection, insert_query,
                      tuple(filtered_scan_data.values()))

    print("Scan results processed successfully.")


def get_git_info():
    """
    Retrieves Git information such as branch name, commit SHA, commit date, repo name, 
    and extracts the service version from mix.exs file.

    Returns:
    - tuple: Contains branch name, commit SHA, commit date, repo name, and service version.
    """
    # GitHub Actions sets the commit SHA in GITHUB_SHA
    commit_sha = os.environ.get('GITHUB_SHA', None)

    if commit_sha:
        commit_sha = commit_sha[:7]

    # GitHub Actions sets the branch or tag ref in GITHUB_REF
    # For branches, it's in the format refs/heads/branch_name
    github_ref = os.environ.get('GITHUB_REF', None)
    ref_parts = github_ref.split('/')

    # Check if the ref is a branch
    if len(ref_parts) > 2 and ref_parts[1] == 'heads':
        branch_name = ref_parts[2]
    else:
        branch_name = None

    try:
        commit_date = subprocess.check_output(
            ['git', 'show', '-s', '--format=%ci', commit_sha], text=True).strip()
    except subprocess.CalledProcessError:
        commit_date = None

    try:
        remote_url = subprocess.check_output(['git',
                                              'config',
                                              '--get',
                                              'remote.origin.url'], text=True).strip()
        repo_name = remote_url.split('/')[-1].replace('.git', '')
    except subprocess.CalledProcessError:
        repo_name = None

    mix_exs_path = 'mix.exs'  # Path to the mix.exs file
    version = None
    try:
        with open(mix_exs_path, 'r') as mix_file:
            mix_contents = mix_file.read()
            version_match = re.search(r' version:\s*"([^\+]+)', mix_contents)
            if version_match:
                version = version_match.group(1).strip()
    except Exception as e:
        print(f"An error occurred while reading {mix_exs_path}: {e}")

    return branch_name, commit_sha, commit_date, repo_name, version


def get_tool_versions_info():
    """
    Reads a file containing languages and their versions, separated by a space.
    Each line in the file is expected to be in the format "language version".

    :return: A list of tuples, where each tuple contains (language, version).
    """
    tool_versions = []
    with open('.tool-versions', 'r') as file:
        for line in file:
            parts = line.strip().split(' ')
            if len(parts) == 2:
                tool_versions.append((parts[0], parts[1]))
    return tool_versions


def read_json_file(file_path):
    """
    Reads JSON content from a file.

    Parameters:
    - file_path (str): Path to the JSON file.

    Returns:
    - dict or None: The JSON content as a dictionary, or None if an error occurs.
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error reading JSON from {file_path}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred when reading {file_path}: {e}")
    return None


def mix_deps_audit(output):
    """
    Analyzes the output from a mix dependencies audit.

    Parameters:
    - output (dict): The audit output.

    Returns:
    - tuple: Number of vulnerabilities found and their details in JSON format.
    """
    vulnerabilities = []
    if not output['pass']:
        for vul in output['vulnerabilities']:
            advisory = vul['advisory']
            dependency = vul['dependency']
            vulnerabilities.append({
                "name": advisory['package'],
                "current_ver": dependency['version'],
                "patched_ver": advisory['first_patched_versions'],
                "severity": advisory['severity']
            })
        return (len(output['vulnerabilities']), json.dumps(vulnerabilities, indent=2))
    else:
        return (0, json.dumps("no vulnerable dependencies"))


def sobelow(output):
    """
    Analyzes the output from a security tool.

    Parameters:
    - output (dict): The audit output.

    Returns:
    - tuple: Number of findings found and their details in JSON format.
    """
    findings = []
    confidence_levels = ['high_confidence',
                         'medium_confidence', 'low_confidence']

    for level in confidence_levels:
        for finding in output['findings'][level]:
            findings.append({
                "confidence": level,
                "type": finding['type'],
                "file": finding['file'],
                "line": finding['line'],
            })

    return (output['total_findings'], json.dumps(findings, indent=2))


def main(folder_path, service_name):
    """
    Main function to process scan results and update the database.

    Parameters:
    - folder_path (str): Path to the folder containing the deps_audit.json file.
    - service_name (str): Name of the service. 

    Returns:
    - None
    """
    host = os.environ.get('SEC_DB_HOST', 'localhost')
    user = os.environ.get('SEC_DB_USER', 'root')
    password = os.environ.get('SEC_DB_PW', '')
    database = os.environ.get('SEC_DB', 'security_dashboard')
    connection = create_connection(host, user, password, database)

    branch_name, commit_sha, commit_date, repo_name, service_version = get_git_info()
    today_date = datetime.now().strftime('%Y-%m-%d')

    languages = get_tool_versions_info()

    if any(language.lower() == 'elixir' for language, version in languages):
        file_path = os.path.join(folder_path, 'deps_audit.json')
        result_data = read_json_file(file_path)
        if result_data:
            mix_audit_nb_vul, mix_audit_vulnerabilities = mix_deps_audit(
                result_data)
        else:
            print("Failed to read or process deps_audit.json")

        file_path = os.path.join(folder_path, 'sobelow.json')
        result_data = read_json_file(file_path)
        if result_data:
            sobelow_nb_vul, sobelow_vulnerabilities = sobelow(result_data)
        else:
            print("Failed to read or process sobelow.json")

    scan_data = {
        'CommitSHA': commit_sha,
        'VersionNumber': service_version,
        'DateOfCommit': commit_date,
        'DateOfScan': today_date,
        'DateOfLastPartialScan': today_date,
        'MixAuditJSONResults': mix_audit_vulnerabilities if mix_audit_vulnerabilities else 'no vulnerable dependencies',
        'MixAuditVulnerabilities': mix_audit_nb_vul,
        'sobelow_json_results': sobelow_vulnerabilities if sobelow_vulnerabilities else 'no code vulnerabilities',
        'sobelow_vulnerabilities': sobelow_nb_vul
    }

    insert_or_update_scan_results(connection, repo_name, scan_data)
    check_and_create_service(connection, repo_name, service_name)
    update_service_branch_sha(connection, repo_name, branch_name, commit_sha)


if __name__ == "__main__":
    if len(sys.argv) >= 1:
        main(os.environ.get('GITHUB_WORKSPACE', None), sys.argv[1])
    else:
        print("Please provide the service name as an argument")
