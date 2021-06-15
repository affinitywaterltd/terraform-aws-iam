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
  name                 = "AWLAdminRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

resource "aws_iam_role_policy_attachment" "admin_role_policy_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SysOps Role

resource "aws_iam_role" "sysops_role" {
  count                 = var.enable_awlsysopsrole ? 1 : 0
  name                 = "AWLSysOpsRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

resource "aws_iam_role_policy_attachment" "sysops_read_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_ec2full_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_rds_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_amazonmq_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonMQFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_ssm_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_s3_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_support_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_awsbackup_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_awslambda_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_awsbeanstalk_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk"
}

resource "aws_iam_role_policy_attachment" "sysops_resourcegroups_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/ResourceGroupsandTagEditorFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_elastisearch_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonElastiCacheFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_fsx_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonFSxFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_datasync_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSDataSyncFullAccess"
}

resource "aws_iam_role_policy_attachment" "sysops_marketplace_policy_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSMarketplaceRead-only"
}

resource "aws_iam_policy" "sysops_ec2_serial_console_policy" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  name        = "sysops_ec2_serial_console"
  description = "Allows SysOps to use EC2 Serial Console"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSerialConsoleAccess",
            "Effect": "Allow",
            "Action": [
                "ec2-instance-connect:SendSerialConsoleSSHPublicKey"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "sysops_ec2_serial_console_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = aws_iam_policy.sysops_ec2_serial_console_policy.0.arn
}


# Allow FlowLog Filter Policy

resource "aws_iam_policy" "sysops_dynamodb_full_access_policy" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  name        = "sysops_dynamodb_full_access"
  description = "Allows SysOps Role to full access to DynamoDB"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowFullDynamoDBAccess",
            "Effect": "Allow",
            "Action": "dynamodb:*",
            "Resource": "*"
        }
    ]
}
POLICY
}


resource "aws_iam_role_policy_attachment" "sysops_dynamodb_full_access_attach" {
  count      = var.enable_awlsysopsrole ? 1 : 0
  role       = aws_iam_role.sysops_role.0.name
  policy_arn = aws_iam_policy.sysops_dynamodb_full_access_policy.0.arn
}


# DBA Role

resource "aws_iam_role" "dba_role" {
  count                = var.enable_awldatabaseanalystrole ? 1 : 0
  name                 = "AWLDatabaseAnalystRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

resource "aws_iam_role_policy_attachment" "dba_read_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "dba_admin_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/DatabaseAdministrator"
}

resource "aws_iam_role_policy_attachment" "dba_awsbackup_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupAdminPolicy"
}

resource "aws_iam_role_policy_attachment" "dba_awswellarchitected_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/WellArchitectedConsoleFullAccess"
}

resource "aws_iam_role_policy_attachment" "dba_support_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_role_policy_attachment" "dba_athena_policy_attach" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonAthenaFullAccess"
}

resource "aws_iam_policy" "dba_dbmigration_policy" {
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  name        = "DB_Migration_Service"
  description = "Allows DBAs to use Database Migration Service"

  policy = <<POLICY
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
  count      = var.enable_awldatabaseanalystrole ? 1 : 0
  role       = aws_iam_role.dba_role.0.name
  policy_arn = aws_iam_policy.dba_dbmigration_policy.0.arn
}

### ReadOnlyRole

resource "aws_iam_role" "read_only_role" {
  name                 = "AWLReadOnlyRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43199
}

resource "aws_iam_role_policy_attachment" "read_only_role_policy_attach" {
  role       = aws_iam_role.read_only_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

### DevOpsRole

resource "aws_iam_role" "dev_ops_role" {
  count                = var.enable_awldevopsrole ? 1 : 0
  name                 = "AWLDevOpsRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43199
}

resource "aws_iam_role_policy_attachment" "dev_s3_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_lambda_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codecommit_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_apigateway_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator"
}

/*
resource "aws_iam_role_policy_attachment" "dev_codebuild_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codedeploy_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codepipeline_role_policy_attach" {
  role       = "${aws_iam_role.dev_ops_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCodePipelineFullAccess"
}*/

resource "aws_iam_role_policy_attachment" "dev_read_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "dev_translate_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/TranslateFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_polly_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonPollyFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_ecs_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_ecr_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_kinesis_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonKinesisFullAccess"
}

resource "aws_iam_role_policy_attachment" "dev_codeartifact_role_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeArtifactAdminAccess"
}


resource "aws_iam_role_policy_attachment" "dev_support_policy_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_policy" "dev_iam_create_policy" {
  count      = var.enable_awldevopsrole ? 1 : 0
  name        = "dev_create_iam_policy"
  description = "Allows Devs up create IAM policies"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*"
            ],
            "Resource": "*"
        }
    ]
} 
POLICY

}

resource "aws_iam_role_policy_attachment" "dev_iam_code_services_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = aws_iam_policy.dev_iam_code_services_policy.0.arn
}

resource "aws_iam_policy" "dev_iam_code_services_policy" {
  count      = var.enable_awldevopsrole ? 1 : 0
  name        = "dev_iam_code_services_policy"
  description = "Allows Devs permissions from the following roles: AWSCodeCommitFullAccess"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "codedeploy:*",
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "codepipeline:*",
                "cloudformation:DescribeStacks",
                "cloudformation:ListChangeSets",
                "cloudformation:DeleteStack",
                "cloudtrail:CreateTrail",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:StartLogging",
                "codebuild:BatchGetProjects",
                "codebuild:CreateProject",
                "codebuild:ListCuratedEnvironmentImages",
                "codebuild:ListProjects",
                "codecommit:GetBranch",
                "codecommit:GetRepositoryTriggers",
                "codecommit:ListBranches",
                "codecommit:ListRepositories",
                "codecommit:PutRepositoryTriggers",
                "codecommit:GetReferences",
                "codedeploy:GetApplication",
                "codedeploy:BatchGetApplications",
                "codedeploy:GetDeploymentGroup",
                "codedeploy:BatchGetDeploymentGroups",
                "codedeploy:ListApplications",
                "codedeploy:ListDeploymentGroups",
                "devicefarm:GetDevicePool",
                "devicefarm:GetProject",
                "devicefarm:ListDevicePools",
                "devicefarm:ListProjects",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecs:ListClusters",
                "ecs:ListServices",
                "elasticbeanstalk:DescribeApplications",
                "elasticbeanstalk:DescribeEnvironments",
                "iam:ListRoles",
                "iam:GetRole",
                "lambda:GetFunctionConfiguration",
                "lambda:ListFunctions",
                "events:ListRules",
                "events:ListTargetsByRule",
                "events:DescribeRule",
                "opsworks:DescribeApps",
                "opsworks:DescribeLayers",
                "opsworks:DescribeStacks",
                "s3:GetBucketPolicy",
                "s3:GetBucketVersioning",
                "s3:GetObjectVersion",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "sns:ListTopics"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "s3:GetObject",
                "s3:CreateBucket",
                "s3:PutBucketPolicy"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:s3::*:codepipeline-*"
        },
        {
            "Action": [
                "iam:PassRole"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::*:role/service-role/cwe-role-*"
            ],
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "events.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Action": [
                "iam:PassRole"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "codepipeline.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Action": [
                "events:PutRule",
                "events:PutTargets",
                "events:DeleteRule",
                "events:DisableRule",
                "events:RemoveTargets"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:events:*:*:rule/codepipeline-*"
            ]
        },
        {
            "Action": [
                "codebuild:*",
                "codecommit:GetBranch",
                "codecommit:GetCommit",
                "codecommit:GetRepository",
                "codecommit:ListBranches",
                "codecommit:ListRepositories",
                "cloudwatch:GetMetricStatistics",
                "ec2:DescribeVpcs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "events:DeleteRule",
                "events:DescribeRule",
                "events:DisableRule",
                "events:EnableRule",
                "events:ListTargetsByRule",
                "events:ListRuleNamesByTarget",
                "events:PutRule",
                "events:PutTargets",
                "events:RemoveTargets",
                "logs:GetLogEvents",
                "s3:GetBucketLocation",
                "s3:ListAllMyBuckets"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "logs:DeleteLogGroup"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:logs:*:*:log-group:/aws/codebuild/*:log-stream:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:PutParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/CodeBuild/*"
        }
    ]
}
POLICY

}


resource "aws_iam_policy" "dev_ec2_policy" {
  count      = var.enable_awldevopsrole ? 1 : 0
  name        = "dev_ec2_policy"
  description = "Allows Devs to perform some EC2 functions"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances"
            ],
            "Resource": "*"
        }
    ]
} 
POLICY

}

resource "aws_iam_role_policy_attachment" "dev_iam_ec2_attach" {
  count      = var.enable_awldevopsrole ? 1 : 0
  role       = aws_iam_role.dev_ops_role.0.name
  policy_arn = aws_iam_policy.dev_ec2_policy.0.arn
}




#
# Data Engineer Role
#

# Admin Role

resource "aws_iam_role" "data_engineer_role" {
  name                 = "AWLDataEngineerRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

# Lake Formation permissions from https://docs.aws.amazon.com/lake-formation/latest/dg/permissions-reference.html#persona-dl-admin
resource "aws_iam_role_policy_attachment" "lakeformation_role_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLakeFormationDataAdmin"
}

resource "aws_iam_role_policy_attachment" "glue_role_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess"
}

resource "aws_iam_role_policy_attachment" "cloudwatchlogs_role_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "lakeformation_crossaccount_role_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLakeFormationCrossAccountManager"
}

resource "aws_iam_role_policy_attachment" "athena_role_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonAthenaFullAccess"
}

resource "aws_iam_policy" "lakeformation_service_role_iam_policy" {
  name        = "lakeformation_service_role_iam_policy"
  description = "Permit access to LakeFormation Service Role"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "lakeformation.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:PutRolePolicy"
            ],
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/lakeformation.amazonaws.com/AWSServiceRoleForLakeFormationDataAccess"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "lakeformation_service_role_iam_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = aws_iam_policy.lakeformation_service_role_iam_policy.arn
}

resource "aws_iam_policy" "iam_passrole_role_iam_policy" {
  name        = "iam_passrole_role_iam_policy"
  description = "Permit access to PassRole for IAM Role"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PassRolePermissions",
            "Effect": "Allow",
            "Action": [
                "iam:PassRole"
            ],
            "Resource": [
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"
            ]
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "iam_passrole_role_iam_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = aws_iam_policy.iam_passrole_role_iam_policy.arn
}

# Resource modifcation from original AmazonPolicy arn:aws:iam::aws:policy/AmazonRedshiftFullAccess
resource "aws_iam_policy" "redshift_limited_iam_policy" {
  name        = "redshift_limited_iam_policy"
  description = "Permit access to limited Redshift Clusters"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "ec2:DescribeInternetGateways",
                "sns:CreateTopic",
                "sns:Get*",
                "sns:List*",
                "cloudwatch:Describe*",
                "cloudwatch:Get*",
                "cloudwatch:List*",
                "cloudwatch:PutMetricAlarm",
                "cloudwatch:EnableAlarmActions",
                "cloudwatch:DisableAlarmActions",
                "cloudwatch:ListMetrics",
                "cloudwatch:GetMetricWidgetImage",
                "cloudwatch:GetMetricData",
                "tag:GetResources",
                "tag:UntagResources",
                "tag:GetTagValues",
                "tag:GetTagKeys",
                "tag:TagResources",
                "redshift:describe*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "redshift:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:redshift:eu-west-1:739672810541:cluster:ardmrdw1-instance",
                "arn:aws:redshift:eu-west-1:739672810541:cluster:arpawdw1-instance",
                "arn:aws:redshift:eu-west-1:739672810541:cluster:aruawdw1-instance"
            ]
        },
        {
            "Action": [
                "iam:PutRolePolicy"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::739672810541:role/aws-service-role/lakeformation.amazonaws.com/AWSServiceRoleForLakeFormationDataAccess"
            ]
        },
        {
            "Action": [
                "redshift:DescribeClusters"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/redshift.amazonaws.com/AWSServiceRoleForRedshift",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "redshift.amazonaws.com"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "redshift_limited_iam_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = aws_iam_policy.redshift_limited_iam_policy.arn
}


# Resource modifcation from original AmazonPolicy arn:aws:iam::aws:policy/AmazonRedshiftFullAccess
resource "aws_iam_policy" "s3_datalake_iam_policy" {
  name        = "s3_datalake_iam_policy"
  description = "Permit access to awl-datalake s3 bucket"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
         {
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },{
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:ListBucketVersions"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::aw-datalake"
        }, 
        {
            "Action": [
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:GetObjectVersion"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::aw-datalake/*"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "s3_datalake_iam_policy_attach" {
  role       = aws_iam_role.data_engineer_role.name
  policy_arn = aws_iam_policy.s3_datalake_iam_policy.arn
}


# DataScientist Role

resource "aws_iam_role" "datascientist_role" {
  name                 = "AWLDataScientistRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

resource "aws_iam_role_policy_attachment" "scientist_sagemaker_role_policy_attach" {
  role       = aws_iam_role.datascientist_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role_policy_attachment" "scientist_codecommit_role_policy_attach" {
  role       = aws_iam_role.datascientist_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

resource "aws_iam_role_policy_attachment" "scientist_s3_role_policy_attach" {
  role       = aws_iam_role.datascientist_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# Network Engineer Role

resource "aws_iam_role" "networkengineer_role" {
  name                 = "AWLNetworkEngineerRole"
  assume_role_policy   = data.aws_iam_policy_document.SSO_trust.json
  max_session_duration = 43200
}

resource "aws_iam_role_policy_attachment" "networkengineer_role_policy_attach" {
  role       = aws_iam_role.networkengineer_role.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

# Allow FlowLog Filter Policy

resource "aws_iam_policy" "allow_flowlog_filter_policy" {
  name        = "allow_flowlog_filter"
  description = "Allows Network Engineer Role to use Flow Log Filter"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowFlowLogFilterAccess",
            "Effect": "Allow",
            "Action": "logs:FilterLogEvents",
            "Resource": "*"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "networkengineer_role_allow_flowlog_policy_attach" {
  role       = aws_iam_role.networkengineer_role.name
  policy_arn = aws_iam_policy.allow_flowlog_filter_policy.0.arn
}