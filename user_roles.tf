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
  name               = "AWLAdminRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
}

resource "aws_iam_role_policy_attachment" "admin_role_policy_attach" {
  role       = "${aws_iam_role.admin_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SysOps Role

resource "aws_iam_role" "sysops_role" {
  name               = "AWLSysOpsRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
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

# DBA Role

resource "aws_iam_role" "dba_role" {
  name               = "AWLDatabaseAnalystRole"
  assume_role_policy = "${data.aws_iam_policy_document.SSO_trust.json}"
}

resource "aws_iam_role_policy_attachment" "dba_read_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "dba_redshift_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "dba_rds_policy_attach" {
  role       = "${aws_iam_role.dba_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}