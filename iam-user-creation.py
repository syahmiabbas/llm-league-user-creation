import hashlib
from datetime import datetime, timedelta

import boto3
import csv
import time

import json
import botocore

def generate_aws_password():
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-_=+[]{};:,.<>?'
    # AWS default: 20 chars, at least one upper, lower, digit, special
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(20))
        if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in '!@#$%^&*()-_=+[]{};:,.<>?' for c in password)):
            return password

def has_login_profile(client, user_name):
    try:
        # Attempt to get login profile
        response = client.get_login_profile(UserName=user_name)

        # If this point is reached, the user has a login profile (console password)
        print(f"The user {user_name} has a password set for console login.")
        return True

    except client.exceptions.NoSuchEntityException:
        # NoSuchEntityException is thrown if the user does not have a login profile
        print(f"The user {user_name} does NOT have a password set for console login.")
        return False
    except Exception as e:
        # Handle other possible exceptions
        print(f"An error occurred: {e}")
        return False

def create_iam_group(iam_client, group_name):
    try:
        # Check if the group already exists
        iam_client.get_group(GroupName=group_name)
        print(f"IAM group '{group_name}' already exists.")
    except iam_client.exceptions.NoSuchEntityException:
        # Create the group if it doesn't exist
        iam_client.create_group(GroupName=group_name)
        print(f"IAM group '{group_name}' created successfully.")


def attach_policy_to_group(iam_client, group_name):
    # Attach the 'LLMLeagueDefaultMultiUserAccess' policy to the group, creating it if needed
    # Attach the group policy to match user-stack.ts
    group_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "sagemaker:List*",
                        "datazone:*",
                        "sagemaker:DescribeDomain",
                        "bedrock:*",
                        "sagemaker:CreatePresignedDomainUrl"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Deny",
                    "Action": [
                        "datazone:GetDomain",
                        "datazone:ListDomains",
                        "datazone:GetProject",
                        "aws-portal:*",
                        "datazone:ListProjects",
                        "datazone:ListEnvironments",
                        "datazone:GetEnvironment"
                    ],
                    "Resource": "*"
                }
            ]
        }
    # Create or update the inline policy for the group
    try:
        iam_client.put_group_policy(
            GroupName=group_name,
            PolicyName="LOLUsersCommonPolicy",
            PolicyDocument=json.dumps(group_policy_document)
        )
        print(f"Attached LOLUsersCommonPolicy to group '{group_name}'")
    except Exception as e:
        print(f"Failed to attach LOLUsersCommonPolicy to group '{group_name}': {e}")
    # Attach the password change policy
    iam_client.attach_group_policy(
        GroupName=group_name,
        PolicyArn='arn:aws:iam::aws:policy/IAMUserChangePassword'
    )
    print("added manage own password user policy")
    print(f"Policy attached to IAM group '{group_name}' successfully.")


def create_iam_user(iam_client, username, password, reset_password, group_name=None, s3_client=None):
    def _create_iam_user_inner(retry_count=0, max_retries=5):
        has_password = has_login_profile(iam_client, username)
        try:
            # Create the IAM user
            cu_response = iam_client.create_user(UserName=username)
            print(f"IAM user '{username}' created successfully.")
            time.sleep(5)  # Wait 5 seconds after user creation to avoid IAM propagation issues
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f"User '{username}' already exists. Skipping user creation.")
                pass
            elif e.response['Error']['Code'] == 'EntityTemporarilyUnmodifiable':
                if retry_count < max_retries:
                    wait_time = 20 + retry_count * 10
                    print(f"User entity temporarily unmodifiable for {username}, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    return _create_iam_user_inner(retry_count + 1, max_retries)
                else:
                    print(f"Max retries reached for user {username} creation. Skipping.")
                    return
            else:
                raise e

        if reset_password or not has_password:
            try:
                profile_creation_response = iam_client.create_login_profile(UserName=username, Password=password, PasswordResetRequired=reset_password)
                print(f"Login profile for user '{username}' created successfully.")
                time.sleep(5)  # Wait 5 seconds after login profile creation to avoid IAM propagation issues
                login_profile_exists = True
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'EntityAlreadyExists':
                    print(f"Login profile for user '{username}' already exists. Skipping login profile creation.")
                    login_profile_exists = True
                elif e.response['Error']['Code'] == 'EntityTemporarilyUnmodifiable':
                    if retry_count < max_retries:
                        wait_time = 20 + retry_count * 10
                        print(f"Login profile temporarily unmodifiable for {username}, retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        return _create_iam_user_inner(retry_count + 1, max_retries)
                    else:
                        print(f"Max retries reached for login profile creation for {username}. Skipping.")
                        return
                else:
                    raise e

        if group_name:
            # Ensure the group exists before adding the user
            try:
                iam_client.get_group(GroupName=group_name)
            except iam_client.exceptions.NoSuchEntityException:
                try:
                    iam_client.create_group(GroupName=group_name)
                    print(f"IAM group '{group_name}' created successfully.")
                except Exception as e:
                    print(f"Failed to create group '{group_name}': {e}")
            # Add the user to the specified IAM group
            try:
                iam_client.add_user_to_group(GroupName=group_name, UserName=username)
                print(f"User '{username}' added to group '{group_name}' successfully.")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    print(f"Group '{group_name}' does not exist. Skipping group addition for user '{username}'.")
                elif e.response['Error']['Code'] == 'EntityTemporarilyUnmodifiable':
                    if retry_count < max_retries:
                        wait_time = 20 + retry_count * 10
                        print(f"Group temporarily unmodifiable for {group_name}, retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        return _create_iam_user_inner(retry_count + 1, max_retries)
                    else:
                        print(f"Max retries reached for group addition for {username}. Skipping.")
                        return
                else:
                    raise e


        
    _create_iam_user_inner()


def main():
    # Use the named profile "skylab" from AWS CLI configuration
    session = boto3.Session(profile_name='profile')
    iam_client = session.client('iam')

    # Name of the IAM group for LLM league users and admin users
    llm_group_name = 'LLM_League_Users'
    admin_group_name = 'Administrators'

    # One-time setup: Create the IAM groups and attach the policies
    create_iam_group(iam_client, llm_group_name)
    attach_policy_to_group(iam_client, llm_group_name)
    
    # Attach AmazonDynamoDBReadOnlyAccess policy to LLM_League_Users group
    try:
        iam_client.attach_group_policy(
            GroupName=llm_group_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess'
        )
        print(f"AmazonDynamoDBReadOnlyAccess policy attached to group '{llm_group_name}'.")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"AmazonDynamoDBReadOnlyAccess policy already attached to group '{llm_group_name}'.")
        else:
            print(f"Failed to attach AmazonDynamoDBReadOnlyAccess policy to group '{llm_group_name}': {e}")
    create_iam_group(iam_client, admin_group_name)

    # Attach AdministratorAccess policy to the Administrators group
    try:
        iam_client.attach_group_policy(
            GroupName=admin_group_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        print(f"AdministratorAccess policy attached to group '{admin_group_name}'.")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"AdministratorAccess policy already attached to group '{admin_group_name}'.")
        else:
            print(f"Failed to attach AdministratorAccess policy to group '{admin_group_name}': {e}")

    # CSV file path containing user information (username,password,group)
    csv_file = 'user_list.csv'

    credentials_output = []

    try:
        with open(csv_file, 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                username = row['username']
                password = generate_aws_password()
                # Use group from CSV if present, else default to LLM_League_Users
                user_group = row['group'] if row['group'] else llm_group_name
                
                # Check if reset_password is specified in the CSV
                reset_password = False
                if 'reset_password' in row and isinstance(row['reset_password'], bool):
                    reset_password = row['reset_password']

                is_admin = False
                if 'admin' in row and str(row['admin']).strip().lower() == 'true':
                    is_admin = True
                if is_admin:
                    # Admin user: add to Administrators group only
                    credentials_output.append({
                        'username': username,
                        'password': password,
                        'group': admin_group_name,
                        'admin': is_admin
                    })
                    create_iam_user(iam_client, username, password, reset_password=reset_password, group_name=admin_group_name)
                    print(f"Admin user '{username}' created and added to the group '{admin_group_name}'. Admin: {is_admin}")
                else:
                    # Non-admin user: add to their group and LLM_League_Users
                    credentials_output.append({
                        'username': username,
                        'password': password,
                        'group': f"{user_group},{llm_group_name}" if user_group != llm_group_name else llm_group_name,
                        'admin': is_admin
                    })
                    create_iam_user(iam_client, username, password, reset_password=reset_password, group_name=user_group)
                    if user_group != llm_group_name:
                        try:
                            iam_client.add_user_to_group(GroupName=llm_group_name, UserName=username)
                            print(f"User '{username}' also added to group '{llm_group_name}'.")
                        except botocore.exceptions.ClientError as e:
                            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                                print(f"User '{username}' is already in group '{llm_group_name}'.")
                            elif e.response['Error']['Code'] == 'NoSuchEntity':
                                print(f"Group '{llm_group_name}' does not exist.")
                            else:
                                print(f"Failed to add user '{username}' to group '{llm_group_name}': {e}")
                    print(f"User '{username}' created and added to the group(s) '{user_group}, {llm_group_name}'. Admin: {is_admin}")

        # Write credentials to a CSV file (append mode)
        output_file = 'user_credentials_output.csv'
        file_exists = False
        try:
            with open(output_file, 'r') as checkfile:
                file_exists = checkfile.readline() != ''
        except FileNotFoundError:
            file_exists = False

        with open(output_file, 'a', newline='') as outfile:
            fieldnames = ['username', 'password', 'group', 'admin']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)

            if not file_exists:
                writer.writeheader()
            for credential in credentials_output:
                writer.writerow(credential)

        print("User credentials have been appended to 'user_credentials_output.csv'.")
    except Exception as e:
        print(f"Error processing CSV file: {e}")

if __name__ == "__main__":
    main()