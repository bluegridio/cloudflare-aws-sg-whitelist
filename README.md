# Cloudflare IP Updater for AWS Security Groups

This is a Python script designed to update AWS security group policies with Cloudflare IP addresses.

## Description

This AWS Lambda function updates the inbound rules of one or more AWS Security Groups to allow traffic from Cloudflare IP addresses.

## Installation

1. Clone this repository:

```bash
git clone https://github.com/bluegridio/cloudflare-aws-sg-whitelist.git
```

2. Create an IAM role with the necessary permissions for the Lambda function to modify Security Groups.
## IAM Policies Used

The following IAM policies are used for managing security group rules:

### For authorizing and revoking security group ingress

- **Policy Name:** CloudflareSecurityGroupManagement
- **Permissions:**
    - `ec2:AuthorizeSecurityGroupIngress`
    - `ec2:RevokeSecurityGroupIngress`
- **Resource:** `arn:aws:ec2:[your-aws-region]:[your-aws-id]:security-group/[your-security-group-id]`

### For describing security groups

- **Policy Name:** DescribeSecurityGroups
- **Permissions:**
    - `ec2:DescribeSecurityGroups`
- **Resource:** All resources (`*`)


3. Set up environment variables(you can navigate to Lambda Function > Configuration > Environment variables and set Key+Value there):

   - `SECURITY_GROUP_IDS_LIST`: Comma-separated list of AWS Security Group IDs.
   - `PORTS_LIST`: Comma-separated list of TCP ports to open (default is `443`).
   - Optionally, set `UPDATE_IPV6` to `0` to disable IPv6 updates.

4. Deploy the Lambda function to your AWS account.

## Usage

This Lambda function is triggered by an event (e.g., EventBridge) or can be invoked manually.

## Contributing

This project is not open for contributions. However, feel free to fork the repository and make changes for personal use.

