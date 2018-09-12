##############
#EC2
##############

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

# Standard EC2 role for servers to be managed by SSM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "SSM_Role"

  assume_role_policy = "${data.aws_iam_policy_document.ec2_assume_role_policy.json}"
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_role_policy_attach" {
  role       = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_instance_profile" "ec2_ssm_role" {
  name = "ssm_role"
  role = "${aws_iam_role.ec2_ssm_role.name}"
}

# 

#