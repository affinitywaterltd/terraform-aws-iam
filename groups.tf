# Global Administrator User
resource "aws_iam_group" "administrator_iam_group" {
  name = "global_administrator"
}

resource "aws_iam_group_policy_attachment" "global_administrator_iam_group_attachment" {
  group      = aws_iam_group.administrator_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Code Commit Power User
resource "aws_iam_group" "codecommit_poweruser_iam_group" {
  name = "codecommit_poweruser"
}

resource "aws_iam_group_policy_attachment" "codecommit_poweruser_iam_group_attachment" {
  group      = aws_iam_group.codecommit_poweruser_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

# Code Artifact Admin Access
resource "aws_iam_group" "codeartifact_adminaccess_iam_group" {
  name = "codeartifact_adminaccess"
}

resource "aws_iam_group_policy_attachment" "codeartifact_adminaccess_iam_group_attachment" {
  group      = aws_iam_group.codeartifact_adminaccess_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeArtifactAdminAccess"
}

# Code Commit Data Power User
resource "aws_iam_group" "codecommit_data_poweruser_iam_group" {
  name = "codecommit_data_poweruser"
}

resource "aws_iam_group_policy_attachment" "codecommit__datapoweruser_iam_group_attachment" {
  group      = aws_iam_group.codecommit_data_poweruser_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

# Code Commit Restrcted Pull Requests
resource "aws_iam_group" "codecommit_enforcefullrequests_iam_group" {
  name = "codecommit_enforcefullrequests"
}

resource "aws_iam_group_policy_attachment" "codecommit_enforcefullrequests_iam_group_attachment" {
  group      = aws_iam_group.codecommit_enforcefullrequests_iam_group.name
  policy_arn = aws_iam_policy.codecommit_enforcefullrequests_iam_policy.arn
}

resource "aws_iam_policy" "codecommit_enforcefullrequests_iam_policy" {
  name        = "codecommit_enforcefullrequests_iam_policy"
  description = "Enforces developers to perform a pull request if the CodeCommit is tagged"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "codecommit:GitPush",
        "codecommit:DeleteBranch",
        "codecommit:PutFile",
        "codecommit:MergeBranchesByFastForward",
        "codecommit:MergeBranchesBySquash",
        "codecommit:MergeBranchesByThreeWay"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCaseIfExists": {
          "codecommit:References": [
            "refs/heads/master",
            "refs/heads/prod",
            "refs/heads/preprod",
            "refs/heads/uat",
            "refs/heads/development"
          ]
        },
        "Null": {
          "codecommit:References": false
        }
      }
    }
  ]
}
POLICY

}

# Code Commit ReadOnly User
resource "aws_iam_group" "codecommit_readonlyuser_iam_group" {
  name = "codecommit_readonlyuser"
}

resource "aws_iam_group_policy_attachment" "codecommit_readonlyuser_iam_group_attachment" {
  group      = aws_iam_group.codecommit_readonlyuser_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitReadOnly"
}

resource "aws_iam_group_membership" "codecommit_readonlyuser_iam_group_membership" {
  name = "codecommit_readonlyuser_iam_group_membership"

  users = [
    aws_iam_user.codecommit_jira_user.name
  ]

  group = aws_iam_group.codecommit_readonlyuser_iam_group.name
}


# SES Send User
resource "aws_iam_group" "ses_sendingaccess_iam_group" {
  name = "ses_sendingaccess"
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

resource "aws_iam_group_policy_attachment" "ses_sendingaccess_iam_group_attachment" {
  group      = aws_iam_group.ses_sendingaccess_iam_group.name
  policy_arn = aws_iam_policy.ses_smtp_user.arn
}

resource "aws_iam_group_membership" "ses_sendingaccess_iam_group_membership" {
  name = "ses_sendingaccess_iam_group_membership"

  users = [
    aws_iam_user.ses_smtp_user.name
  ]

  group = aws_iam_group.ses_sendingaccess_iam_group.name
}

# Solarwinds User
resource "aws_iam_group" "app_solarwinds_iam_group" {
  name = "app_solarwinds"
}

resource "aws_iam_policy" "solarwinds_monitor_user" {
  name = "app_solarwinds_policy"

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

resource "aws_iam_group_policy_attachment" "app_solarwinds_iam_group_attachment" {
  group      = aws_iam_group.app_solarwinds_iam_group.name
  policy_arn = aws_iam_policy.solarwinds_monitor_user.arn
}

resource "aws_iam_group_membership" "app_solarwinds_iam_group_membership" {
  name = "app_solarwinds_iam_group_membership"

  users = [
    aws_iam_user.solarwinds_monitor_user.name
  ]

  group = aws_iam_group.app_solarwinds_iam_group.name
}

# CitrixMachineCreation User
resource "aws_iam_group" "app_citrix_machine_creation_iam_group" {
  name = "app_citrix_machine_creation"
}

resource "aws_iam_policy" "app_citrix_machine_creation" {
  name = "app_citrix_machine_creation"

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

resource "aws_iam_group_policy_attachment" "app_citrix_machine_creation_iam_group_attachment" {
  group      = aws_iam_group.app_citrix_machine_creation_iam_group.name
  policy_arn = aws_iam_policy.app_citrix_machine_creation.arn
}

resource "aws_iam_group_membership" "app_citrix_machine_creation_iam_group_membership" {
  name = "app_citrix_machine_creation_iam_group_membership"

  users = [
    aws_iam_user.citrix_machine_creation.name
  ]

  group = aws_iam_group.app_citrix_machine_creation_iam_group.name
}

# ECS Exec Group
resource "aws_iam_group" "ecs_cli_admin_iam_group" {
  name = "ecs_cli_admin"
}

resource "aws_iam_policy" "ecs_cli_admin" {
  name = "ecs_cli_admin"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
 {
      "Action": [
        "ecs:DescribeTasks",
        "ecs:ExecuteCommand"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_group_policy_attachment" "ecs_cli_admin_iam_group_attachment" {
  group      = aws_iam_group.ecs_cli_admin_iam_group.name
  policy_arn = aws_iam_policy.ecs_cli_admin.arn
}


# ECS Exec Group
resource "aws_iam_group" "s3_admin_iam_group" {
  name = "s3_admin_iam_group"
}

resource "aws_iam_policy" "s3_admin" {
  name = "s3_admin"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
 {
      "Action": [
        "s3:Get*",
        "s3:Put*",
        "s3:Delete*",
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_group_policy_attachment" "s3_admin_iam_group_attachment" {
  group      = aws_iam_group.s3_admin_iam_group.name
  policy_arn = aws_iam_policy.s3_admin.arn
}