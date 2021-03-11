# Global Administrator User
resource "aws_iam_group" "administrator_iam_group" {
  name = "global_administrator"
}

resource "aws_iam_group_policy_attachment" "global_administrator_iam_group_attachment" {
  group      = aws_iam_group.administrator_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Code Commit Power User
resource "aws_iam_group" "codecommit_poweruser_iam_group" {
  name = "codecommit_poweruser"
}

resource "aws_iam_group_policy_attachment" "codecommit_poweruser_iam_group_attachment" {
  group      = aws_iam_group.codecommit_poweruser_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

# Code Artifact Admin Access
resource "aws_iam_group" "codeartifact_adminaccess_iam_group" {
  name = "codeartifact_adminaccess"
}

resource "aws_iam_group_policy_attachment" "codeartifact_adminaccess_iam_group_attachment" {
  group      = aws_iam_group.codeartifact_adminaccess_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeArtifactAdminAccess"
}

# Code Commit Data Power User
resource "aws_iam_group" "codecommit_data_poweruser_iam_group" {
  name = "codecommit_data_poweruser"
}

resource "aws_iam_group_policy_attachment" "codecommit__datapoweruser_iam_group_attachment" {
  group      = aws_iam_group.codecommit_data_poweruser_iam_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

# Code Commit Restrcted Pull Requests
resource "aws_iam_group" "codecommit_enforcefullrequests_iam_group" {
  name = "codecommit_enforcefullrequests"
}

resource "aws_iam_group_policy_attachment" "codecommit_enforcefullrequests_iam_group_attachment" {
  group      = aws_iam_group.codecommit_enforcefullrequests_iam_group.name
  policy_arn = aws_iam_policy.codecommit_enforcefullrequests_iam_policy.arn
}

resource "aws_iam_policy" "codecommit_enforcefullrequests_iam_policy" {
  name        = "codecommit_enforcefullrequests_iam_policy"
  description = "Enforces developers to perform a pull request if the CodeCommit is tagged"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "codecommit:GitPush",
        "codecommit:DeleteBranch",
        "codecommit:PutFile",
        "codecommit:MergeBranchesByFastForward",
        "codecommit:MergeBranchesBySquash",
        "codecommit:MergeBranchesByThreeWay"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCaseIfExists": {
          "codecommit:References": [
            "refs/heads/master",
            "refs/heads/prod",
            "refs/heads/preprod",
            "refs/heads/uat",
            "refs/heads/development"
          ]
        },
        "Null": {
          "codecommit:References": false
        }
      }
    }
  ]
}
POLICY

}

# Code Commit ReadOnly User
resource "aws_iam_group" "codecommit_readonlyuser_iam_group" {
  name = "codecommit_readonlyuser"
}

resource "aws_iam_group_membership" "codecommit_readonlyuser_iam_group_membership" {
  name = "codecommit_readonlyuser_iam_group_membership"

  users = [
    aws_iam_user.codecommit_jira_user.name
  ]

  group = aws_iam_group.codecommit_readonlyuser_iam_group.name
}

# SES Send User
resource "aws_iam_group" "ses_sendingaccess_iam_group" {
  name = "ses_sendingaccess"
}

resource "aws_iam_group_membership" "ses_sendingaccess_iam_group_membership" {
  name = "ses_sendingaccess_iam_group_membership"

  users = [
    aws_iam_user.ses_smtp_user.name
  ]

  group = aws_iam_group.ses_sendingaccess_iam_group.name
}