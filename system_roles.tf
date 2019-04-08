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
