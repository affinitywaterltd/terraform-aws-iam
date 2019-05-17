##############
#EC2
##############

# Standard EC2 role for servers to be managed by SSM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "SSM_Role"

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
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_role_policy_attachment" "ec2_read_role_policy_attach" {
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "sns_full_role_policy_attach" {
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_iam_instance_profile" "ec2_ssm_role" {
  name = "ssm_role"
  role = "${aws_iam_role.ec2_ssm_role.name}"
}


resource "aws_iam_policy" "ec2_tags_create" {
  name = "EC2TagsCreate"
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
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "${aws_iam_policy.ec2_tags_create.arn}"
}


resource "aws_iam_policy" "ec2_snapshot" {
  name = "EC2Snapshot"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:DeleteSnapshot",
                "ec2:ModifySnapshotAttribute",
                "ec2:CreateSnapshot",
                "ssm:GetParameter"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "s3_bucket_ssm_scripts" {
  name = "S3SSMScripts"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "s3:Get*",
            "Resource": "arn:aws:s3:::aw-ssm-logs"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "s3_bucket_ssm_scripts_role_policy_attach" {
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "${aws_iam_policy.s3_bucket_ssm_scripts.arn}"
}

resource "aws_iam_role_policy_attachment" "ec2_snapshot_role_policy_attach" {
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "${aws_iam_policy.ec2_snapshot.arn}"
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

  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

resource "aws_iam_role_policy_attachment" "lambda_readonly_policy_attach" {
  role       = "${aws_iam_role.lambda_reporting_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_ses_policy_attach" {
  role       = "${aws_iam_role.lambda_reporting_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_sns_policy_attach" {
role = "${aws_iam_role.lambda_reporting_role.name}"
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
    ignore_changes = ["assume_role_policy"]
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
  name = "sophos_central_aws"
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
  role       = "${aws_iam_role.sophos_central_aws.name}"
  policy_arn = "${aws_iam_policy.sophos_central_aws.arn}"
} 

###################
#Citrix-Smart-Scale
###################

# Citrix Smart Scale 

resource "aws_iam_role" "citrix_smart_scale" {
  name = "Citrix-Smart-Scale"
  lifecycle {
    ignore_changes = ["assume_role_policy"]
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
  name = "Citrix_Smart_Scale_pol"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:DisassociateAddress",
                "ec2:RebootInstances",
                "sns:*",
                "iam:GetRole",
                "ec2:DescribeInstances",
                "ec2:DescribeAddresses",
                "ec2:DetachNetworkInterface",
                "ec2:StopInstances",
                "autoscaling-plans:*",
                "sqs:*",
                "iam:SimulatePrincipalPolicy",
                "ec2:DescribeNetworkInterfaces",
                "ec2:StartInstances",
                "ec2:AttachNetworkInterface",
                "ec2:AssociateAddress"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "citrix_smart_scale_role_policy_attach" {
  role       = "${aws_iam_role.citrix_smart_scale.name}"
  policy_arn = "${aws_iam_policy.Citrix_Smart_Scale.arn}"
} 
 