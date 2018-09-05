# Account identity
data "aws_caller_identity" "current" {}



# EC2 role policy
data "aws_iam_policy_document" "ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Local to save time

locals {
  ec2_assume_role = "${data.aws_iam_policy_document.ec2_assume_role_policy.json}"
}
