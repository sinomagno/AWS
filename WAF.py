from boto3 import session
from sso import gatheraccountlist, get_credentials, create_session, Connect_to_AWS_Service, active_region, convert_list_to_string, gatheraccoultrolelist
import os
import csv
from typing import List, Any
import re
import signal
import sys
from progress.bar import IncrementalBar

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


def create_session_keys(account, role_account):
    """
        Receive an account number
        Return the accessKeyId, secretAccessKey, sessionToken
        of the AWS authentication
    """

    get_credentials(account, role_account)
    credentials = get_credentials(account, role_account)
    
    Session = create_session(str(credentials['roleCredentials']['accessKeyId']),
                             str(credentials['roleCredentials']['secretAccessKey']),
                             str(credentials['roleCredentials']['sessionToken']))
    
    return Session


def get_waf_acls(rule_waf_acls):
    """
     :param A list of WEBACLs deployed for an account WAF.
     :return baseline rule (AWS-AWSManagedRulesCommonRuleSet, AWS-AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet) and the metrics name.
    """
    base_line_rule = []
    MetricName = []
    ExcludeRules = list()

    for rule in rule_waf_acls['Rules']:
        rule_name = ''

        rule_name = 'AWS-AWSManagedRulesCommonRuleSet'*('AWS-AWSManagedRulesCommonRuleSet' in rule['Name']) + 'AWS-AWSManagedRulesSQLiRuleSet'*('AWS-AWSManagedRulesSQLiRuleSet' in rule['Name'] ) + 'AWSManagedRulesKnownBadInputsRuleSet'*('AWSManagedRulesKnownBadInputsRuleSet' in rule['Name'])
        if rule_name:
            base_line_rule.append(rule_name)
            dict_excludedRules = rule['Statement']['ManagedRuleGroupStatement'].get('ExcludedRules', '')
            
            if isinstance(dict_excludedRules,list):
                for excludedrules in dict_excludedRules:
                    ExcludeRules.append(excludedrules['Name'])

        MetricName.append(rule['VisibilityConfig'].get('MetricName'))

    return base_line_rule, MetricName, ExcludeRules


def get_elb_attached(web_acl_arn, waf_service):

    elb_name = list()
    attached_resource = waf_service.list_resources_for_web_acl(
        WebACLArn=web_acl_arn
    )

    if isinstance(attached_resource['ResourceArns'], list):
        for arn in attached_resource.get('ResourceArns'):
            match = re.split(r'/', arn)
            elb_name.append(match[2])

    return elb_name, attached_resource['ResourceArns']


def get_elb(Session, elbv2_arn, region):
    
    elbv2_listener_dict = {}

    elb = Connect_to_AWS_Service(Session, 'elbv2', region)
    for arn in elbv2_arn:
        elbv2_Protocol = list()
        elbv2_SSLPolicy = list()
        elbv2_Port = list()

        elbv2_listeners=elb.describe_listeners(
            LoadBalancerArn=arn
        )
        for elbv2_listener in elbv2_listeners['Listeners']:
            elbv2_Protocol.append(elbv2_listener.get('Protocol', ' '))
            elbv2_SSLPolicy.append(elbv2_listener.get('SslPolicy', ' '))
            elbv2_Port.append(elbv2_listener.get('Port', ' '))

            elbv2_listener_dict=({"ELB_Name": re.split(r'/', arn)[2], 'Elastic Load balancer Protocol':elbv2_Protocol,'SslPolicy':elbv2_SSLPolicy, 'Port':elbv2_Port})
    
    return(elbv2_listener_dict)


def get_waf_list(account, region, Session, subscription_name):
    """
    :Param account id, region, session and the subscription name
    :return a list of WAFs
    """
    waf_list = list()
    rule_logging = False
    Waf_get_web_acl = {}
    elbv2_arn = list()

    waf_service = Connect_to_AWS_Service(Session, 'wafv2', region)

    Waf_List_web_acls: object = waf_service.list_web_acls(
        Scope='REGIONAL'
    )
    
    if isinstance(Waf_List_web_acls['WebACLs'], list):
        for waf_acls in Waf_List_web_acls['WebACLs']:
            
            base_line_compliance = False

            web_acl_name = waf_acls.get('Name',' ')
            web_acl_id = waf_acls.get('Id',' ')
            web_acl_arn = waf_acls.get('ARN',' ')

            Waf_get_web_acl = waf_service.get_web_acl(
                Name=web_acl_name,
                Scope='REGIONAL',
                Id=web_acl_id
            )
            
            elb_names, elbv2_arn = get_elb_attached(web_acl_arn, waf_service)
            elb_attached = convert_list_to_string(elb_names, ',')
            
            elastic_load_balancer = get_elb(Session, elbv2_arn, region)

            SampledRequestsEnabled = Waf_get_web_acl['WebACL']['VisibilityConfig']['SampledRequestsEnabled']
            CloudWatchMetricsEnabled = Waf_get_web_acl['WebACL']['VisibilityConfig']['CloudWatchMetricsEnabled']
            MetricName = Waf_get_web_acl['WebACL']['VisibilityConfig'].get('MetricName', '')

            base_line_rule, rule_MetricName, ExcludedRules1 = get_waf_acls(Waf_get_web_acl['WebACL'])
            if len(base_line_rule) == 3:
                base_line_compliance = True
            
            if len(rule_MetricName) == len (Waf_get_web_acl['WebACL']['Rules']):
                rule_logging = True
            
            baseline_rules = convert_list_to_string(base_line_rule, ',')
            
            ExcludedRules = convert_list_to_string(ExcludedRules1, ',')

            waf_list.append({'Subscription Name': subscription_name, 'Account': account, 'Web ACL Name': web_acl_name, 'WAF Sampled Requests Enabled': SampledRequestsEnabled, 'CloudWatchMetricsEnabled': CloudWatchMetricsEnabled, 'MetricName': MetricName, 'AWS Basic Rules': base_line_compliance, 'All Rules login': rule_logging, 'ELB Attached': elb_attached, 'ELB config': elastic_load_balancer,'AWS enabled': baseline_rules, 'ExcludedRules': ExcludedRules,'Region': region})

    return waf_list


def export_to_excel(list_with_info):
    """
        Receive a list of dictionaries to create an excel file in a fixed path
    """
    file_path = r"C:\Users\Sinomagno\Documents\WAF.csv"
    file_exists = os.path.isfile(file_path)
    with open(file_path, 'a+', newline='') as csv_resource_list:
            fieldnames = ['Subscription Name', 'Account', 'Web ACL Name', 'WAF Sampled Requests Enabled', 'CloudWatchMetricsEnabled', 'MetricName', 'AWS Basic Rules', 'All Rules login', 'ExcludedRules', 'AWS enabled', 'ELB Attached', 'ELB config','Region']
            csv_writer = csv.DictWriter(csv_resource_list, fieldnames=fieldnames) 
            if not file_exists:
                 csv_writer.writeheader()
        
            for list_resource in list_with_info:
                csv_writer.writerow(list_resource)
            csv_resource_list.close()


def main_program(Allaccounts):
    """
    :Param List of accounts
    :return a list of dictionary with the information necessary
    """
    bar = IncrementalBar('Account processed', max = len(Allaccounts))
        
    for account_dict in Allaccounts:
        
        Active_region = list()
        waf_list = list()

        account = account_dict['accountId']
        subscription_name = account_dict['accountName']

        role = gatheraccoultrolelist(account)
        Session = create_session_keys(account, role)

        Active_region = active_region(Session)

        for region in Active_region:
            waf_list = get_waf_list(account, region, Session, subscription_name)
        
        export_to_excel(waf_list)
        
        bar.next()
        
    bar.finish()
        

if __name__ == '__main__':
    """
        Program start
    """
    Allaccounts = gatheraccountlist()
    
    if isinstance(Allaccounts, List):
        main_program(Allaccounts)
    else:
        print("Not able to gather the list of accounts assigned to")
        exit(1)
    
