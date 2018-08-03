# Standard EC2 role to be managed by SSM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "ssm_role"

  assume_role_policy = "${local.ec2_assume_role}"
}

resource "aws_iam_role_policy_attachment" "sto-readonly-role-policy-attach" {
  role = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_instance_profile" "ec2_ssm_role" {
  name = "ssm_role"                                    # Change this to remove the 2
  role = "${aws_iam_role.ec2_ssm_role.name}"
}