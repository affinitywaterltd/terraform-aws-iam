#### Citrix Machine Creation ####

resource "aws_iam_user" "citrix_machine_creation" {
  name          = "CitrixMachineCreation"
  force_destroy = true
}

resource "aws_iam_user_policy" "citrix_machine_creation" {
  name = "CitrixMachineCreation"
  user = aws_iam_user.citrix_machine_creation.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
 {
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateImage",
        "ec2:CreateNetworkInterface",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteNetworkInterface",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DetachVolume",
        "ec2:RebootInstances",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RunInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

#SES User
resource "aws_iam_user" "ses_smtp_user" {
  name          = "ses_smtp_user"
  force_destroy = true
}

resource "aws_iam_user_policy" "ses_smtp_user" {
  user = aws_iam_user.ses_smtp_user.name
  name = "SesSendingAccess"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "ses:SendRawEmail",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "ses_smtp_user" {
  name = "ses_sending_access"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "ses:SendRawEmail",
            "Resource": "*"
        }
    ]
}
EOF
}

#SolarWinds User
resource "aws_iam_user" "solarwinds_monitor_user" {
  name          = "SolarWinds_Monitor"
  force_destroy = true
}

resource "aws_iam_user_policy" "solarwinds_monitor_user" {
  user = aws_iam_user.solarwinds_monitor_user.name
  name = "SolarWinds_Monitor"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeAddresses",
                "ec2:DescribeVolumes",
                "ec2:DescribeVolumeStatus",
                "cloudwatch:GetMetricStatistics",
                "autoscaling:DescribeAutoScalingInstances"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}


resource "aws_iam_user" "codecommit_jira_user" {
  name          = "code_commit_jira_user"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "codecommit_jira_user_policy_attachmeent" {
  user       = aws_iam_user.codecommit_jira_user.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitReadOnly"
}