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

variable "enable_awldevopsrole" {
  description = "Conditional creation of role"
  default     = true
}

variable "enable_awlsysopsrole" {
  description = "Conditional creation of role"
  default     = true
}

variable "enable_awldatabaseanalystrole" {
  description = "Conditional creation of role"
  default     = true
}