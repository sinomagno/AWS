from typing import Any, List
from sso import gatheraccountlist, active_region, get_credentials, Connect_to_AWS_Service, create_session
import csv
import os


def export_to_excel(list_with_info):
    """
        Receive a list of dictionaries to create an excel file in a fixed path
    """
    file_path = r"C:\Users\Sinomagno\Documents\WAF_subscriptions.csv"

    file_exists = os.path.isfile(file_path)
    with open(file_path, 'a+', newline='') as csv_resource_list:
            fieldnames = ['Subscription Name', 'Account id']
            csv_writer = csv.DictWriter(csv_resource_list, fieldnames=fieldnames) 
            if not file_exists:
                 csv_writer.writeheader()
        
            for list_resource in list_with_info:
                csv_writer.writerow(list_resource)
            csv_resource_list.close()


def create_session_keys(account):
    """
        Receive an account number
        Return the accessKeyId, secretAccessKey, sessionToken
        of the AWS authentication
    """
    Role = "Sino_role"

    if get_credentials(account, Role) != "Error":
        credentials = get_credentials(account, Role)
    elif get_credentials(account, "Sino_role1") != "Error":
        credentials = get_credentials(account, "Sino_role1")
    else:
        credentials = get_credentials(account, "Sino_role2")

    Session = create_session(str(credentials['roleCredentials']['accessKeyId']),
                             str(credentials['roleCredentials']['secretAccessKey']),
                             str(credentials['roleCredentials']['sessionToken']))
    
    return Session


def main_program(list_account):
    """
    :Param List of AWS account
    Start to retrieve the information from each AWS account
    """
    excel_info = list()
    
    for account in list_account:
        account_aliases = {}
        Active_region = list()
        subscription_name = ''

        print(account)
        Session = create_session_keys(account)
        print(Session)
        Active_region = active_region(Session)
        iam = Connect_to_AWS_Service(Session, 'iam', 'us-east-1')
        account_aliases = iam.list_account_aliases()
        
        if account_aliases['AccountAliases']:
            subscription_name = account_aliases['AccountAliases'][0]

        excel_info.append({'Subscription Name': subscription_name, 'Account id': account})
    
    export_to_excel(excel_info)    


if __name__=='__main__':
    """
        Program start
    """
    Allaccounts: List[Any] = gatheraccountlist()
    
    if isinstance(Allaccounts, List):
        main_program(Allaccounts)
    else:
        print("Not able to gather the list of accounts assigned to")
        exit(1)
    
