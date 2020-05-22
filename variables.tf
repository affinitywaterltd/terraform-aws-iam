# Account identity
data "aws_caller_identity" "current" {
}

variable "centralised_logging_s3_bucket" {
  description = "Name of S3 bucket used for centalised logging"
  default     = null
}

variable "local_logging_s3_bucket" {
  description = "Name of S3 bucket used for local account logging"
  default     = null
}