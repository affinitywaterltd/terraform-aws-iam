# Trust document for SSO and cross account access

data "aws_iam_policy_document" "SSO_trust" {
  statement {
    sid = "OneLogin"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type = "Federated"
      identifiers = "arn:aws:iam::${data.aws_caller_identity.account_id}:saml-provider/Azure_AD"
    }

    condition {
      test = "StringEquals"
      variable = "SAML:aud"
      values = ["https://signin.aws.amazon.com/saml"]
    }
  }

  statement {
    sid = "acme"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::739672810541:root"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "admin_role_policy_attach" {
  role = "${aws_iam_role.admin_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Admin Role

resource "aws_iam_role" "admin_role" {
  name                = "AWLAdminRole"
  assume_role_policy  =  "${data.aws_iam_policy_document.SSO_trust.json}"

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
  name = "ssm_role"                                   
  role = "${aws_iam_role.ec2_ssm_role.name}"
}

# 