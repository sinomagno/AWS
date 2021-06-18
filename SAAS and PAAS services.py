from sso import get_credentials, Connect_to_AWS_Service, gatheraccountlist, active_region


def create_session_keys(account):
    """
        Receive an account number
        Return the accessKeyId, secretAccessKey, sessionToken
        of the AWS authentication

        SinoUser = Role assigned in the SSO
    """
    credentials = get_credentials(account, "SinoUser")

    Session = create_session(str(credentials['roleCredentials']['accessKeyId']),
                             str(credentials['roleCredentials']['secretAccessKey']),
                             str(credentials['roleCredentials']['sessionToken']))
    
    return Session


def get_tag(KeyName_Value, instance_tags):
    """
        Receive an string which is the Key to look for into a dictionary, ussualy the instance['Tags'].
        Return the Value os the key or '0' if the key is not found.
    """
    tag = [d['Value'] for d in instance_tags if (d['Key']).upper() == KeyName_Value]
    if not tag:
        tag.append(0)
    
    return str(tag[0])


def get_list_buckets(session, region, subscription_name, account):
    """
        Receive a session, region, subscription name, and account id
        Return a list of dictionaries with the information of the bukets in the AWS account
    """
    s3_list_bucket = list()

    s3_bucket = Connect_to_AWS_Service(session, 's3', region)
    list_s3 = s3_bucket.list_buckets()
    buckets = list_s3.get('Buckets', '')
    
    if isinstance(buckets, list):
        for bucket in buckets:
            excel_columns = dict()
            excel_columns = {'Account': account, 'Subscription Name': subscription_name, 'Type': 'S3', 'Name': bucket.get('Name', ''), 'Location': 'Global'}
            if excel_columns:
                s3_list_bucket.append(excel_columns)
    
    return s3_list_bucket


def waf_inforamtion(session, region, subscription_name, account):
    """
        Gather the list of all Web ACL applied in the WAF
    """
    waf_web_acl_list = list()
    
    waf_service = Connect_to_AWS_Service(session, 'wafv2', region)
    Waf_List_web_acls: object = waf_service.list_web_acls(
        Scope='REGIONAL'
    )

    if Waf_List_web_acls['WebACLs']:
        for web_acl in  Waf_List_web_acls['WebACLs']:
            waf_web_acl_list.append({'Account': account, 'Subscription Name': subscription_name, 'Type': 'WAF Web ACL', 'Name': web_acl.get('Name', ''), 'Location': region})
    
    return waf_web_acl_list


def main_program(Allaccounts):
    """
        Receive a list of accounts that we are going to process and gather the information.
    """
    account = ''
    
    for account in Allaccounts:
        account_aliases = {}
        row = list()
        Active_region = list()
        subscription_name = ''
        full_list = []

        print(account)
        Session = create_session_keys(account)

        Active_region = active_region(Session)
        iam = Connect_to_AWS_Service(Session, 'iam', 'us-east-1')
        account_aliases = iam.list_account_aliases()

        if account_aliases['AccountAliases']:
            subscription_name = account_aliases['AccountAliases'][0]
        
        for region in Active_region:
            bucket_list = get_list_buckets(Session, region, subscription_name, account)
            full_list.append(bucket_list)
            waf_list = waf_inforamtion(Session, region, subscription_name, account)
            full_list.append(waf_list)

        print(full_list)


if __name__ == '__main__':
    """
        Begin of the program
    """
    Allaccounts: List[Any] = gatheraccountlist()

    if isinstance(Allaccounts, List):
        main_program(Allaccounts)
    else:
        print("Not able to gather the list of accounts assigned to")
        exit(1)
