# Cloudflare IP Updater for AWS Security Groups

The Cloudflare IP Updater for AWS Security Groups is a Python script developed to enhance the security of AWS resources by ensuring that only traffic originating from Cloudflare IP addresses is allowed to access specified ports (e.g., port 443). By updating AWS security group policies dynamically with the latest Cloudflare IP addresses, this script helps protect the origin server from exposure to unauthorized access.

## How It Works

The script retrieves the latest list of Cloudflare IP addresses using the Cloudflare API. It then updates the specified AWS security groups with the retrieved IP addresses, allowing inbound traffic only from these trusted sources.

## Features

- Automatic retrieval of Cloudflare IP addresses using the Cloudflare API.
- Dynamic updating of AWS security group policies to allow traffic only from Cloudflare IP addresses.
- Support for both IPv4 and IPv6 addresses.
- Email notification feature to alert administrators of successful or failed updates.

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

### For sending emails via AWS SES

- **Policy Name:** ses:SendEmail
- **Permissions:**
    - `ses:SendEmail`
- **Resource:** All resources (`*`)

3. Setting Up Environment Variables

To configure the Cloudflare IP Updater script, follow these steps to set up environment variables:

1. Navigate to your Lambda Function settings.
2. Go to Configuration > Environment variables.
3. Add the following Key+Value pairs:

   - `SECURITY_GROUP_IDS_LIST` or `SECURITY_GROUP_ID`: Comma-separated list of AWS Security Group IDs.
   - `PORTS_LIST`: Comma-separated list of TCP ports to open (default is `443`).
   - Optionally, set `UPDATE_IPV6` to `0` to disable IPv6 updates.
   - `SES_REGION`: Set your AWS SES region. You can find supported regions [here](https://docs.aws.amazon.com/ses/latest/dg/regions.html).
   - `SES_SENDER_EMAIL`: The email address you wish to send emails from.
   - `SES_RECIPIENT_EMAIL`: The email address where notifications will be sent.
   - `WHITELISTED_IPS`: Comma-separated list of IP addresses to whitelist.

Make sure to replace the placeholder values with your actual configuration details. These environment variables are essential for the proper functioning of the Cloudflare IP Updater script.

4. Deploy the Lambda function to your AWS account.

## Usage

This Lambda function is triggered by an event (e.g., EventBridge) or can be invoked manually.

## Contributing

This project is not open for contributions. However, feel free to fork the repository and make changes for personal use.

