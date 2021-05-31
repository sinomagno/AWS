import os
import glob
import json
from typing import List, Any
import botocore.exceptions
import boto3


DefaultRegion = "us-east-1"
sso = boto3.client('sso', region_name=DefaultRegion)
Regions = ["af-south-1", "eu-north-1", "ap-south-1", "eu-west-3", "eu-west-2", "eu-south-1", "eu-west-1",
           "ap-northeast-2", "me-south-1", "ap-northeast-1", "sa-east-1", "ca-central-1", "ap-east-1", "ap-southeast-1",
           "ap-southeast-2", "eu-central-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2"]


def active_region(Session):
    """
    Find the current active region
    :param Session:
    :return:
    """
    r_region = []

    for region in Regions:
        tag = []
        try:
            ec2 = Session.resource('ec2', region_name=region)
            All_instances = ec2.instances.all()
            for instance in All_instances:
                key_value = 'OS'
                tag.append([d['Value'] for d in instance.tags if (d['Key']).upper() == key_value])
        except botocore.exceptions.ClientError as error:
            print(f"Region: ", region, " is not current enabled")
        if tag:
            r_region.append(region)

    return r_region


def get_credentials(AccountId, roleName):
    """
    :param AccountId:
    :param roleName:
    :return: "roleCredentials": {
        "accessKeyId": "ASIAXXXXXXXXXXXXX",
        "secretAccessKey": "",
        "sessionToken": "",
    """
    try:
        return sso.get_role_credentials(
            roleName=roleName,
            accountId=AccountId,
            accessToken=gatheraccesstoken()
        )
    except botocore.exceptions.ClientError as error:
        return "Error"


def gatheraccesstoken():
    """
    - Find Access token in path %USERPROFILE%/.aws/sso/cache/
    :return: Access Token
    """
    Filepath = os.path.join(os.environ['USERPROFILE'], ".aws\\sso\\cache\\*")
    list_of_files = glob.glob(Filepath)
    latest_file = max(list_of_files, key=os.path.getmtime)
    with open(latest_file, 'r') as ssocache:
        info = json.load(ssocache)
    ssocache.close()
    return info.get('accessToken', '')


def gatheroleassignment(ListofAccount):
    """
    Receive the list of accounts to review
    :param ListofAccount:
    Call the function to gather the access token
    :return: a list with all the roles assigned to the account send
    """
    RoleList = []
    for AccountId in ListofAccount:
        Rolelist = sso.list_account_roles(
            accessToken=gatheraccesstoken(),
            accountId=AccountId
        )
        RoleList.append(Rolelist['roleList'])
    return (RoleList)


def gatheraccountlist():
    """
    - Authenticate to AWS using the Access Token
    :return: list with accounts ids
    No parameters are needed to call the function
    """
    Accountlist = []
    AccessToken = gatheraccesstoken()
    if AccessToken:
        List_accounts = sso.list_accounts(
            maxResults=200,
            accessToken=AccessToken
        )
        for listAccount in List_accounts['accountList']:
            Accountlist.append(listAccount['accountId'])
        return Accountlist
    else:
        return "No access token"
        exit(1)


def create_session(accessKeyId, SecretAccessKey, Sessiontoken):
    """
    Update the config file with new profile
    :param accessKeyId:
    :param SecretAccessKey:
    :param Sessiontoken:
    :return:
    """
    session = boto3.Session(
        aws_access_key_id=accessKeyId,
        aws_secret_access_key=SecretAccessKey,
        aws_session_token=Sessiontoken
    )
    return session


def Connect_to_AWS_Service(Session, ServiceName, region):
    """
    Return an AWS service
    :param Session:
    :param ServiceName:
    :param region:
    :return:
    """
    return Session.client(ServiceName, region_name=region)


def convert_list_to_string(List, separator):
    """ Convert list to string, by joining all item in list with given separator.
            Returns the concatenated string """
    return separator.join(List)
