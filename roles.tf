# Admin Role

resource "aws_iam_role" "admin_role" {
  name                = "AWLAdminRole"
  assume_role_policy  =  <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::739672810541:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "admin_role_policy_attach" {
  role = "${aws_iam_role.admin_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Standard EC2 role to be managed by SSM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "SSM_Role"

  assume_role_policy = "${local.ec2_assume_role}"
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_role_policy_attach" {
  role = "${aws_iam_role.ec2_ssm_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_instance_profile" "ec2_ssm_role" {
  name = "ssm_role"                                    # Change this to remove the 2
  role = "${aws_iam_role.ec2_ssm_role.name}"
}