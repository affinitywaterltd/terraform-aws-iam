##############
#EC2
##############

# Standard EC2 role for servers to be managed by SSM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "SSM_Role"
  description = "Default IAM role applied to EC2 instances for SSM Patching and Server build access to resources"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {

      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": [ "ec2.amazonaws.com", "ssm.amazonaws.com" ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_role_policy_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_read_role_policy_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_agent_policy_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_instance_profile" "ec2_ssm_role" {
  name = "ssm_role"
  role = aws_iam_role.ec2_ssm_role.name
}

resource "aws_iam_policy" "ec2_tags_create" {
  name   = "ssm_ec2_create_tags"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:CreateTags",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2_tags_create_role_policy_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = aws_iam_policy.ec2_tags_create.arn
}

resource "aws_iam_policy" "iam_assume_role" {
  name   = "iam_assume_role"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "ssm_s3_bucket" {
  name   = "ssm_s3_bucket"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSSMS3LogsReadWriteAccess",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:GetEncryptionConfiguration",
                "s3:ListBucketMultipartUploads",
                "s3:AbortMultipartUpload",
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:PutObjectAcl",
                "s3:ListMultipartUploadParts"
            ],
            "Resource": [
                "arn:aws:s3:::aw-ssm-logs",
                "arn:aws:s3:::aw-ssm-logs/*"
            ]
        },
        {
            "Sid": "AllowSSMToolingReadAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::aw-tooling",
                "arn:aws:s3:::aw-tooling/*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ssm_s3_bucket_role_policy_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = aws_iam_policy.ssm_s3_bucket.arn
}

###############
#Lambda
###############

# Lambda role policy

data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Lambda reporting role - read and notification

resource "aws_iam_role" "lambda_reporting_role" {
  name = "Lambda_Reporting"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_readonly_policy_attach" {
  role       = aws_iam_role.lambda_reporting_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_ses_policy_attach" {
  role       = aws_iam_role.lambda_reporting_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_sns_policy_attach" {
  role       = aws_iam_role.lambda_reporting_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

###############
#SSM
###############

# SSM Service linked role

resource "aws_iam_service_linked_role" "iam_service_linked_role_for_ssm" {
  aws_service_name = "ssm.amazonaws.com"
}


###################
#Sophos-Central-AWS
###################

# Sophos Central Console Connection Role

resource "aws_iam_role" "sophos_central_aws" {
  name = "Sophos-Central-AWS"
  lifecycle {
    ignore_changes = [assume_role_policy]
  }
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::062897671886:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": ""
        }
      }
    }
  ]
}
EOF

}

resource "aws_iam_policy" "sophos_central_aws" {
  name   = "sophos_central_aws"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetUser",
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "autoscaling:DescribeAutoScalingGroups",
		"s3:ListAllMyBuckets",
		"s3:GetBucketLocation",
		"s3:GetBucketPolicy",
		"s3:GetBucketVersioning",
		"s3:GetEncryptionConfiguration",
		"s3:GetBucketAcl",
		"cloudTrail:DescribeTrails",
		"cloudTrail:GetTrailStatus",
		"cloudTrail:GetEventSelectors",
		"securityhub:BatchImportFindings"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF

}

resource "aws_iam_role_policy_attachment" "sophos_central_aws_role_policy_attach" {
  role       = aws_iam_role.sophos_central_aws.name
  policy_arn = aws_iam_policy.sophos_central_aws.arn
}

###################
#ADC-Citrix-Smart-Scale
###################

# ADC Citrix Smart Scale 

resource "aws_iam_role" "citrix_smart_scale" {
  name = "Citrix-ADC-SmartScale"
  lifecycle {
    ignore_changes = [assume_role_policy]
  }
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_policy" "citrix_smart_scale" {
  name   = "Citrix-ADC-SmartScale-pol"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:SimulatePrincipalPolicy",
        "autoscaling:*",
        "sns:*",
        "sqs:*",
        "cloudwatch:*",
        "ec2:AssignPrivateIpAddresses",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DetachNetworkInterface",
        "ec2:AttachNetworkInterface",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy_attachment" "citrix_smart_scale_role_policy_attach" {
  role       = aws_iam_role.citrix_smart_scale.name
  policy_arn = aws_iam_policy.citrix_smart_scale.arn
}

resource "aws_iam_instance_profile" "citrix_smart_scale_role" {
  name = "Citrix-ADC-SmartScale"
  role = aws_iam_role.citrix_smart_scale.name
}

# -----------------------------------------------------------
# AWS Config Role
# -----------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "awl-config"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY

}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

#
# SSM Maintenance Window snapshot cleanup role
#
resource "aws_iam_role" "lambda_snapshot_cleanup_role" {
  name = "lambda-snapshot-cleanup-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_snapshot_cleaup_policy_attach" {
  role       = aws_iam_role.lambda_snapshot_cleanup_role.name
  policy_arn = aws_iam_policy.ec2_cleanup_snapshot.arn
}

resource "aws_iam_policy" "ec2_cleanup_snapshot" {
  name   = "ec2-cleanup-snapshot"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:DeleteSnapshot",
                "ec2:DeregisterImage",
                "ec2:ModifySnapshotAttribute",
                "ec2:DescribeImages",
                "logs:DescribeLogGroups",
                "logs:PutRetentionPolicy",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# SSM Maintenance Window Updates
#
resource "aws_iam_role" "lambda_maintenance_window_update_role" {
  name = "lambda-maintenance-window-update-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_maintenance_window_update_attach" {
  role       = aws_iam_role.lambda_maintenance_window_update_role.name
  policy_arn = aws_iam_policy.ssm_maintenance_window_update.arn
}

resource "aws_iam_policy" "ssm_maintenance_window_update" {
  name   = "ssm-maintenance-window-update"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ssm:UpdateMaintenanceWindowTask",
                "ssm:GetMaintenanceWindowTask",
                "ssm:GetMaintenanceWindow",
                "logs:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# SSM Start Instances
#
data "aws_iam_policy_document" "ssm_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_maintenance_window_start_instance_role" {
  name = "ssm-maintenance-window-start-instance-role"

  assume_role_policy = data.aws_iam_policy_document.ssm_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "ssm_maintenance_window_start_instance_attach" {
  role       = aws_iam_role.ssm_maintenance_window_start_instance_role.name
  policy_arn = aws_iam_policy.ssm_maintenance_window_start_instances.arn
}

resource "aws_iam_policy" "ssm_maintenance_window_start_instances" {
  name   = "ssm-maintenance-window-start-instances"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# SSM CreateImage
#
resource "aws_iam_role" "ssm_maintenance_window_create_image_role" {
  name = "ssm-maintenance-window-create-image-role"

  assume_role_policy = data.aws_iam_policy_document.ssm_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "ssm_maintenance_window_create_image_attach" {
  role       = aws_iam_role.ssm_maintenance_window_create_image_role.name
  policy_arn = aws_iam_policy.ssm_maintenance_window_create_image.arn
}

resource "aws_iam_policy" "ssm_maintenance_window_create_image" {
  name   = "ssm-maintenance-window-create-image"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:CreateImage",
                "ec2:DescribeImages"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# Lambda Citrix Tagging Role
#
resource "aws_iam_role" "lambda_ec2_tagging_citrix_mcs_servers_role" {
  name = "lambda-ec2-tagging-citrix-mcs-servers-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_ec2_tagging_citrix_mcs_servers_role_attach" {
  role       = aws_iam_role.lambda_ec2_tagging_citrix_mcs_servers_role.name
  policy_arn = aws_iam_policy.lambda_ec2_tagging_citrix_mcs_servers_policy.arn
}

resource "aws_iam_policy" "lambda_ec2_tagging_citrix_mcs_servers_policy" {
  name   = "lambda-ec2-tagging-citrix-mcs-servers"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "ec2:CreateTags",
                "logs:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# CloudWatchLog Expiration Role
#
resource "aws_iam_role" "lambda_cloudwatch_logs_expiration_role" {
  name = "lambda-cloudwatch-logs-expiration-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_cloudwatch_logs_expiration_attach" {
  role       = aws_iam_role.lambda_cloudwatch_logs_expiration_role.name
  policy_arn = aws_iam_policy.lambda_cloudwatch_logs_expiration_policy.arn
}

resource "aws_iam_policy" "lambda_cloudwatch_logs_expiration_policy" {
  name   = "lambda-cloudwatch-logs-expiration"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DeleteLogGroup",
                "logs:PutRetentionPolicy",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

#
# Cloudwatch Monitoring Access
#
resource "aws_iam_role" "app_grafana_cloudwatch_read_role" {
  name               = "app_grafana_cloudwatch_read_role"
  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::986618351900:role/ssm_role_custom_grafana"
            },
            "Action": "sts:AssumeRole"
        },
        {
          "Sid": "",
          "Effect": "Allow",
          "Principal": {
            "Service": [
              "ec2.amazonaws.com",
              "sts.amazonaws.com"
            ]
          },
          "Action": "sts:AssumeRole"
        }
    ]
}
POLICY

}

resource "aws_iam_policy" "app_grafana_policy" {
  name   = "app_grafana_policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadingMetricsFromCloudWatch",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:DescribeAlarmsForMetric",
                "cloudwatch:ListMetrics",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:GetMetricData"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowReadingTagsInstancesRegionsFromEC2",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags",
                "ec2:DescribeInstances",
                "ec2:DescribeRegions"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowReadingResourcesForTags",
            "Effect" : "Allow",
            "Action" : "tag:GetResources",
            "Resource" : "*"
        }
    ]
}
EOF

}

resource "aws_iam_role_policy_attachment" "app_grafana_policy_attachment" {
  role       = aws_iam_role.app_grafana_cloudwatch_read_role.name
  policy_arn = aws_iam_policy.app_grafana_policy.arn
}

#
# RDS Database Enhanced Monitoring Role
#
data "aws_iam_policy_document" "rds_monitoring_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_enhanced_monitoring_role" {
  name = "rds-enhanced-monitoring-role"

  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring_role_attach" {
  role       = aws_iam_role.rds_enhanced_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

#
# ElasticBeanstalk EC2 Role
#
data "aws_iam_policy_document" "elasticbeanstalk_ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "elasticbeanstalk_ec2_role" {
  name = "elasticbeanstalk-ec2-role"

  assume_role_policy = data.aws_iam_policy_document.elasticbeanstalk_ec2_assume_role_policy.json
}

resource "aws_iam_instance_profile" "elasticbeanstalk_ec2_instance_profile" {
  name = "elasticbeanstalk-ec2-instance-profile"
  role = aws_iam_role.elasticbeanstalk_ec2_role.name
}

resource "aws_iam_role_policy_attachment" "elasticbeanstalk_ec2_role_attach" {
  role       = aws_iam_role.elasticbeanstalk_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
}

#
# ElasticBeanbstalk Service Role
#
data "aws_iam_policy_document" "elasticbeanstalk_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["elasticbeanstalk.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "elasticbeanstalk_service_role" {
  name = "elasticbeanstalk-service-role"

  assume_role_policy = data.aws_iam_policy_document.elasticbeanstalk_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "elasticbeanstalk_service_role_attach" {
  role       = aws_iam_role.elasticbeanstalk_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService"
}

#
# AWS Instance Scheduler Role
#

resource "aws_iam_role" "aws_instace_scheduler_role" {
  name = "AWS-Instance-Scheduler-Role"
  lifecycle {
    ignore_changes = [assume_role_policy]
  }
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com",
        "AWS": "arn:aws:iam::986618351900:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_policy" "aws_instace_scheduler_policy" {
  name   = "AWS-Instance-Scheduler-Policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "rds:DeleteDBSnapshot",
                "rds:DescribeDBSnapshots",
                "rds:StopDBInstance"
            ],
            "Resource": "arn:aws:rds:*:${data.aws_caller_identity.current.account_id}:snapshot:*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "rds:AddTagsToResource",
                "rds:RemoveTagsFromResource",
                "rds:DescribeDBSnapshots",
                "rds:StartDBInstance",
                "rds:StopDBInstance"
            ],
            "Resource": "arn:aws:rds:*:${data.aws_caller_identity.current.account_id}:db:*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "rds:AddTagsToResource",
                "rds:RemoveTagsFromResource",
                "rds:StartDBCluster",
                "rds:StopDBCluster"
            ],
            "Resource": [
                "arn:aws:rds:*:${data.aws_caller_identity.current.account_id}:cluster:*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": [
                "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:instance/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "rds:DescribeDBClusters",
                "rds:DescribeDBInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:ModifyInstanceAttribute",
                "ssm:DescribeMaintenanceWindows",
                "ssm:DescribeMaintenanceWindowExecutions",
                "tag:GetResources"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOF

}

resource "aws_iam_role_policy_attachment" "aws_instace_scheduler_policy_attach" {
  role       = aws_iam_role.aws_instace_scheduler_role.name
  policy_arn = aws_iam_policy.aws_instace_scheduler_policy.arn
}


#
# S3 Replication Role
#
resource "aws_iam_role" "s3_accesslogs_bucket_replication_role" {
  name = "s3-accesslogs-bucket-replication-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "s3_accesslogs_bucket_replication_policy" {
  name = "s3-accesslogs-bucket-replication-policy"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${var.local_logging_s3_bucket}"
      ]
    },
    {
      "Action": [
        "s3:GetObjectVersion",
        "s3:GetObjectVersionAcl"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${var.local_logging_s3_bucket}/*"
      ]
    },
    {
      "Action": [
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ObjectOwnerOverrideToBucketOwner"
      ],
      "Effect": "Allow",
      "Resource": [
          "arn:aws:s3:::${var.centralised_logging_s3_bucket}/*",
          "arn:aws:s3:::${var.centralised_logging_s3_bucket}"
      ]
    }
  ]
}
POLICY
}

resource "aws_iam_policy_attachment" "replication" {
  name       = "s3-bucket-replication"
  roles      = [aws_iam_role.s3_accesslogs_bucket_replication_role.name]
  policy_arn = aws_iam_policy.s3_accesslogs_bucket_replication_policy.arn
}


#
# CodeCommit Cross Account Access Role
#
resource "aws_iam_role" "app_cicd_codecommit_access_role" {
  name               = "app_cicd_codecommit_access_role"
  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::633033879498:role/ssm_role_custom_cicd"
            },
            "Action": "sts:AssumeRole"
        },
        {
          "Sid": "",
          "Effect": "Allow",
          "Principal": {
            "Service": [
              "ec2.amazonaws.com",
              "sts.amazonaws.com"
            ]
          },
          "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "app_cicd_codecommit_policy_attachment" {
  role       = aws_iam_role.app_cicd_codecommit_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}
