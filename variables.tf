variable "vpc_id" {
  type        = string
  description = "The VPC that the ECS cluster is in"
}

variable "kms_key_arn" {
  type        = string
  description = "Used for transit and tailscale state encryption"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = <<EOT
The ids for the private subnets that EFS will be deployed into
EOT
}

variable "tailscale_container_image" {
  type        = string
  default     = "ghcr.io/tailscale/tailscale:stable"
  description = <<EOT
The fully qualified container image for tailscale.
EOT
}

variable "port_efs_tailscale_state" {
  type        = number
  default     = 2049
  description = <<EOT
The port number at which the tailscale state efs mount is available
EOT
}

variable "tailscale_serve_enabled" {
  type        = bool
  default     = false
  description = "Whether to Serve"
}

variable "tailscale_serve_upstream_url" {
  type        = string
  default     = null
  description = <<EOT
The url to serve with tailscale serve
EOT
  validation {
    condition     = var.tailscale_serve_enabled ? var.tailscale_serve_upstream_url != null : true
    error_message = "If tailscale_serve_enabled is true, then you must set tailscale_serve_upstream_url"
  }
}

variable "port_tailscale_healthcheck" {
  type        = number
  default     = 7801
  description = <<EOT
The port number for Tailscale health check endpoint
EOT
}

variable "tailscale_tags" {
  type = list(string)

  description = "The list of tags that will be assigned to tailscale node created by this stack."
  validation {
    condition = alltrue([
      for tag in var.tailscale_tags : can(regex("^tag:", tag))
    ])
    error_message = "max_allocated_storage: Each tag in tailscale_tags must start with 'tag:'"
  }
}


variable "tailscale_tailnet" {
  type = string

  description = <<EOT
  description = The tailnet domain (or "organization's domain") for your tailscale tailnet, this s found under Settings > General > Organization
EOT
}

variable "tailscale_client_id" {
  type        = string
  sensitive   = true
  description = "The OIDC client id for tailscale that has permissions to create auth keys with the `tailscale_tags` tags"
}

variable "tailscale_client_secret" {
  type        = string
  sensitive   = true
  description = "The OIDC client secret paired with `tailscale_client_id`"
}

variable "service_connect_configurations" {
  type = list(object({
    enabled   = bool
    namespace = optional(string, null)
    log_configuration = optional(object({
      log_driver = string
      options    = optional(map(string), null)
      secret_option = optional(list(object({
        name       = string
        value_from = string
      })), [])
    }), null)
    service = optional(list(object({
      client_alias = list(object({
        dns_name = string
        port     = number
      }))
      timeout = optional(list(object({
        idle_timeout_seconds        = optional(number, null)
        per_request_timeout_seconds = optional(number, null)
      })), [])
      tls = optional(list(object({
        kms_key  = optional(string, null)
        role_arn = optional(string, null)
        issuer_cert_authority = object({
          aws_pca_authority_arn = string
        })
      })), [])
      discovery_name        = optional(string, null)
      ingress_port_override = optional(number, null)
      port_name             = string
    })), [])
  }))
  description = <<-EOT
    The list of Service Connect configurations.
    See `service_connect_configuration` docs https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#service_connect_configuration
    EOT
  default     = []
}


variable "exec_enabled" {
  type        = bool
  description = "Specifies whether to enable Amazon ECS Exec for the tasks within the service"
  default     = false
}


variable "public_subnet_ids" {
  type        = list(string)
  description = <<EOT
The ids for the public subnets that ECS will be deployed into
EOT
}


variable "ecs_cluster_arn" {
  type        = string
  description = "The ECS cluster ARN this service will be deployed in"
}

variable "tailscale_hostname" {
  type        = string
  default     = null
  description = <<EOT
The hostname for this tailscale device, will default to to the context id
EOT
}

variable "log_group_retention_in_days" {
  default     = 30
  type        = number
  description = <<EOT
The number in days that cloudwatch logs will be retained.
EOT
}

variable "tailscale_ssh_enabled" {
  type        = bool
  description = "Whether to enable tailscale ssh into the tailscale node"
  default     = true
}

variable "tailscale_extra_args" {
  type        = list(string)
  description = <<EOT
TS_EXTRA_ARGS Any other flags to pass in to the Tailscale CLI in a tailscale set command.
See https://tailscale.com/kb/1080/cli#set
EOT
  default     = []
}

variable "tailscaled_extra_args" {
  type        = list(string)
  default     = null
  description = <<EOT
TS_TAILSCALED_EXTRA_ARGS
Any other flags to pass in to tailscaled.
See https://tailscale.com/kb/1278/tailscaled#flags-to-tailscaled
EOT
}

variable "tailscale_routes" {
  type        = string
  default     = null
  description = <<EOT
TS_ROUTES Advertise subnet routes. This is equivalent to tailscale set --advertise-routes=.
EOT
}

variable "tailscale_accept_dns" {
  type        = bool
  default     = false
  description = <<EOT
TS_ACCEPT_DNS Accept DNS configuration from the admin console. Not accepted by default.
EOT
}
