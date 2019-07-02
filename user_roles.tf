# Trust document for SSO and cross account access

data "aws_iam_policy_document" "SSO_trust" {
  statement {
    sid     = "OneLogin"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/Azure_AD"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = ["https://signin.aws.amazon.com/saml"]
    }
  }

  statement {
    sid     = "acme"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::739672810541:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

# Admin Role

resource "aws_iam_role" "admin_role" {
  name                  = "AWLAdminRole"
  assume_role_policy    = "${data.aws_iam_policy_document.SSO_trust.json}"
  max_session_duration  = 43200
}

resource "aws_iam_role_policy_attachment" "admin_role_policy_attach" {
  role       = "${aws_iam_role.admin_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SysOps Role

resource "aws_iam_role" "sysops_role" {
  name               = "AWLSysOpsRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
  max_session_duration  = 43200
}

resource "aws_iam_role_policy_attachment" "sysops_read_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_ec2full_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_rds_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_amazonmq_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonMQFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_ssm_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_s3_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_support_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_awsbackup_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupAdminPolicy"
}

resource "aws_iam_role_policy_attachment" "sysops_awslambda_policy_attach" {
  role       = "${aws_iam_role.sysops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

# DBA Role

resource "aws_iam_role" "dba_role" {
  name               = "AWLDatabaseAnalystRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
  max_session_duration  = 43200
}

resource "aws_iam_role_policy_attachment" "dba_read_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "dba_admin_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/job-function/DatabaseAdministrator"
}

resource "aws_iam_role_policy_attachment" "dba_awsbackup_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupAdminPolicy"
}


resource "aws_iam_policy" "dba_dbmigration_policy" {
  name        = "DB_Migration_Service"
  description = "Allows DBAs to use Database Migration Service"

  policy      = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "dms:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:ListAliases", 
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:PassRole",
                "iam:CreateRole",
                "iam:AttachRolePolicy"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVpcs",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:Get*",
                "cloudwatch:List*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:FilterLogEvents",
                "logs:GetLogEvents"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "redshift:Describe*",
                "redshift:ModifyClusterIamRoles"
            ],
            "Resource": "*"
        }
    ]
} 
POLICY
}

resource "aws_iam_role_policy_attachment" "dba_dms_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "${aws_iam_policy.dba_dbmigration_policy.arn}"
}


/*
resource "aws_iam_role_policy_attachment" "dba_redshift_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "s3_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "dba_rds_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_iam_role_policy_attachment" "dba_sns_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_iam_policy" "dba_dbmigration_policy" {
  name        = "DBAMigrationService"
  description = "Allows DBAs to use Database Migration Service"

  policy      = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "cloudwatch:List*",
                "redshift:ModifyClusterIamRoles",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "dms:*",
                "iam:PassRole",
                "redshift:Describe*",
                "kms:ListAliases",
                "logs:GetLogEvents",
                "kms:DescribeKey",
                "logs:FilterLogEvents",
                "cloudwatch:Get*"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "dba_dms_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "${aws_iam_policy.dba_dbmigration_policy.arn}"
}


resource "aws_iam_policy" "dba_parametergroup_policy" {
  name        = "DBAParameterGroup"
  description = "Allows DBAs to create and assign parameter groups"

  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "iam:*",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "rds.amazonaws.com"
                }
            }
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "dba_rds_parameter_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "${aws_iam_policy.dba_parametergroup_policy.arn}"
}
*/


### ReadOnlyRole

resource "aws_iam_role" "read_only_role" {
  name               = "AWLReadOnlyRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
  max_session_duration  = 43199
}

resource "aws_iam_role_policy_attachment" "read_only_role_policy_attach" {
  role       = "${aws_iam_role.read_only_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}


### DevOpsRole

resource "aws_iam_role" "dev_ops_role" {
  name               = "AWLDevOpsRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
  max_session_duration  = 43199
}

resource "aws_iam_role_policy_attachment" "dev_s3_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_lambda_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codebuild_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codecommit_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codedeploy_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codepipeline_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodePipelineFullAccess"
}
resource "aws_iam_role_policy_attachment" "dev_read_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
