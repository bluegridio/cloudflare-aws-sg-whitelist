import os
import boto3
import json
import urllib3


def get_cloudflare_ip_list():
    http = urllib3.PoolManager()
    response = http.request('GET', 'https://api.cloudflare.com/client/v4/ips')
    temp = json.loads(response.data.decode('utf-8'))
    if 'result' in temp:
        return temp['result']
    raise Exception("Cloudflare response error")

def get_aws_security_group(group_id):
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group
    raise Exception('Failed to retrieve Security Group')

def check_ipv4_rule_exists(rules, address, port):
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False

def add_ipv4_rule(group, address, port):
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [
                    {
                        'CidrIp': address,
                        'Description': 'from https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name))

def delete_ipv4_rule(group, address, port):
    group.revoke_ingress(IpProtocol="tcp",
                          CidrIp=address,
                          FromPort=port,
                          ToPort=port)
    print("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name))

def check_ipv6_rule_exists(rules, address, port):
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False

def add_ipv6_rule(group, address, port):
    group.authorize_ingress(
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'Ipv6Ranges': [
                    {
                        'CidrIpv6': address,
                        'Description': 'from https://api.cloudflare.com/client/v4/ips'
                    },
                ]
            },
        ]
    )
    print("Added %s : %i to %s (%s) " % (address, port, group.group_id, group.group_name))

def delete_ipv6_rule(group, address, port):
    group.revoke_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print("Removed %s : %i from %s (%s) " % (address, port, group.group_id, group.group_name))

def get_update_ipv6():
    try:
        return bool(int(os.environ['UPDATE_IPV6']))
    except (KeyError, ValueError):
        return True

def update_security_group_policies(ip_addresses):
  print("Checking policies of Security Groups")

  try:
    security_groups = os.environ['SECURITY_GROUP_IDS_LIST']
  except KeyError:
    try:
      security_groups = os.environ['SECURITY_GROUP_ID']
    except KeyError:
      print('Missing environment variables SECURITY_GROUP_IDS_LIST and SECURITY_GROUP_ID. Will not update security groups.')
      return

  security_groups = map(get_aws_security_group, security_groups.split(','))

  try:
    ports = os.environ['PORTS_LIST']
  except KeyError:
    ports = '443'

  ports = map(int, ports.split(','))

  if (not ports) or (not security_groups):
    raise Exception('At least one TCP port and one security group ID are required.')

  for security_group in security_groups:
    current_rules = security_group.ip_permissions
    for port in ports:
      for ipv4_cidr in ip_addresses['ipv4_cidrs']:
        if not check_ipv4_rule_exists(current_rules, ipv4_cidr, port):
          add_ipv4_rule(security_group, ipv4_cidr, port)

      for rule in current_rules:
        if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
          for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] not in ip_addresses['ipv4_cidrs']:
              delete_ipv4_rule(security_group, ip_range['CidrIp'], port)

      if get_update_ipv6():
        for ipv6_cidr in ip_addresses['ipv6_cidrs']:
          if not check_ipv6_rule_exists(current_rules, ipv6_cidr, port):
            add_ipv6_rule(security_group, ipv6_cidr, port)

        for rule in current_rules:
          if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == port and rule['ToPort'] == port:
            for ip_range in rule['Ipv6Ranges']:
              if ip_range['CidrIpv6'] not in ip_addresses['ipv6_cidrs']:
                delete_ipv6_rule(security_group, ip_range['CidrIpv6'], port)


def lambda_handler(event, context):
    security_group_id = os.environ.get('SECURITY_GROUP_ID')
    ip_addresses = get_cloudflare_ip_list()
    update_security_group_policies(ip_addresses)