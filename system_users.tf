#### Citrix Machine Creation ####
resource "aws_iam_user" "citrix_machine_creation" {
  name          = "CitrixMachineCreation"
  force_destroy = true
}

#SES User
resource "aws_iam_user" "ses_smtp_user" {
  name          = "ses_smtp_user"
  force_destroy = true
}

#SolarWinds User
resource "aws_iam_user" "solarwinds_monitor_user" {
  name          = "SolarWinds_Monitor"
  force_destroy = true
}

#CodeCommit JIRA User
resource "aws_iam_user" "codecommit_jira_user" {
  name          = "code_commit_jira_user"
  force_destroy = true
}
