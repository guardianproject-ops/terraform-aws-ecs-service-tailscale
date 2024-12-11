locals {
  tailscale_environment = [
    {
      name = "TS_EXTRA_ARGS"
      value = join(" ",
        concat(
          var.tailscale_extra_args,
          var.tailscale_ssh_enabled ? ["--ssh"] : []
        )
      )
    },
    {
      name  = "TS_TAILSCALED_EXTRA_ARGS"
      value = var.tailscaled_extra_args
    },
    {
      name  = "TS_ROUTES"
      value = var.tailscale_routes
    },
    {
      name  = "TS_ACCEPT_DNS"
      value = var.tailscale_accept_dns ? "true" : null
    },
    {
      name  = "TS_STATE_DIR"
      value = "/var/lib/tailscale"
    },
    {
      name  = "TS_SOCKET"
      value = "/var/run/tailscale/tailscaled.sock"
    },
    {
      name  = "TS_HOSTNAME"
      value = coalesce(var.tailscale_hostname, module.this.id)
    },
    {
      name  = "TS_USERSPACE",
      value = "true"
    },
    {
      name  = "TS_SOCKS5_SERVER"
      value = "localhost:1055"
    },
    {
      name  = "TS_OUTBOUND_HTTP_PROXY_LISTEN"
      value = "localhost:1055"
    },
    {
      name  = "TS_LOCAL_ADDR_PORT"
      value = "0.0.0.0:${var.port_tailscale_healthcheck}"
    },
    {
      name  = "TS_ENABLE_METRICS"
      value = "true"
    },
    {
      name  = "TS_ENABLE_HEALTH_CHECK"
      value = "true"
    },
    {
      name  = "TS_SERVE_CONFIG"
      value = var.tailscale_serve_enabled ? "/config/serve.json" : null
    }
  ]
}
module "label_ssm_params_tailscale" {
  source    = "cloudposse/label/null"
  version   = "0.25.0"
  delimiter = "/"
  context   = module.this.context
}

module "label_log_group_tailscale" {
  source     = "cloudposse/label/null"
  version    = "0.25.0"
  delimiter  = "/"
  attributes = ["tailscale"]
  context    = module.this.context
}

module "label_log_group_tailscale_init" {
  source     = "cloudposse/label/null"
  version    = "0.25.0"
  delimiter  = "/"
  attributes = ["tailscale-init"]
  context    = module.this.context
}

resource "aws_cloudwatch_log_group" "tailscale" {
  count             = module.this.enabled ? 1 : 0
  name              = "/${module.label_log_group_tailscale.id}"
  retention_in_days = var.log_group_retention_in_days
  tags              = module.this.tags
}

resource "aws_cloudwatch_log_group" "tailscale_init" {
  count             = module.this.enabled ? 1 : 0
  name              = "/${module.label_log_group_tailscale_init.id}"
  retention_in_days = var.log_group_retention_in_days
  tags              = module.this.tags
}

resource "aws_security_group" "tailscale" {
  count       = module.this.enabled ? 1 : 0
  name        = "${module.this.id}-tailscale-ingress"
  description = "Security group for tailscale ingress"
  vpc_id      = var.vpc_id
  tags        = merge(module.this.tags, { "Name" : "${module.this.id}-tailscale-ingress" })
}

resource "aws_vpc_security_group_egress_rule" "tailscale_egress_all" {
  count             = module.this.enabled ? 1 : 0
  security_group_id = aws_security_group.tailscale[0].id
  ip_protocol       = "-1" # -1 means all protocols
  from_port         = -1
  to_port           = -1
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow all egress traffic"
}

resource "aws_vpc_security_group_ingress_rule" "tailscale_tailscale" {
  count             = module.this.enabled ? 1 : 0
  security_group_id = aws_security_group.tailscale[0].id
  from_port         = 41641
  to_port           = 41641
  ip_protocol       = "udp"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow all inbound tailscale"
}
resource "aws_security_group" "tailscale_to_efs_state" {
  count       = module.this.enabled ? 1 : 0
  name        = "${module.this.id}-to-efs-state"
  description = "Security group for ECS to EFS access"
  vpc_id      = var.vpc_id
  tags        = merge(module.this.tags, { "Name" : "${module.this.id}-to-efs-state" })
}

resource "aws_vpc_security_group_egress_rule" "tailscale_to_efs_state_egress_all" {
  count             = module.this.enabled ? 1 : 0
  security_group_id = aws_security_group.tailscale_to_efs_state[0].id
  ip_protocol       = "-1" # -1 means all protocols
  from_port         = -1
  to_port           = -1
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow all egress traffic"
}

resource "aws_vpc_security_group_ingress_rule" "tailscale_to_efs_state_tailscale" {
  count                        = module.this.enabled ? 1 : 0
  security_group_id            = aws_security_group.tailscale_to_efs_state[0].id
  referenced_security_group_id = aws_security_group.tailscale[0].id
  from_port                    = var.port_efs_tailscale_state
  to_port                      = var.port_efs_tailscale_state
  ip_protocol                  = "tcp"
  description                  = "Allow ECS to access EFS from tailscale"
}

resource "aws_efs_file_system" "tailscale_state" {
  count          = module.this.enabled ? 1 : 0
  creation_token = module.this.id
  encrypted      = true
  kms_key_id     = var.kms_key_arn
  tags           = module.this.tags
}

resource "aws_efs_access_point" "tailscale_state" {
  count          = module.this.enabled ? 1 : 0
  file_system_id = aws_efs_file_system.tailscale_state[0].id
  root_directory {
    path = "/${module.this.id}"
    creation_info {
      owner_uid   = 0
      owner_gid   = 0
      permissions = "770"
    }
  }
  posix_user {
    uid = 0
    gid = 0
  }
  tags = module.this.tags
}

resource "aws_efs_mount_target" "tailscale_state" {
  count           = module.this.enabled ? length(var.private_subnet_ids) : 0
  file_system_id  = aws_efs_file_system.tailscale_state[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.tailscale_to_efs_state[0].id]
}

module "tailscale_def" {
  source          = "cloudposse/ecs-container-definition/aws"
  version         = "0.61.1"
  container_name  = "tailscale"
  container_image = var.tailscale_container_image
  essential       = true

  container_depends_on = [
    {
      condition     = "SUCCESS"
      containerName = "tailscale-init"
    }
  ]
  mount_points = [
    {
      containerPath = "/var/lib/tailscale"
      readOnly      = false
      sourceVolume  = "tailscale-state"
    },
    {
      containerPath = "/config"
      readOnly      = true
      sourceVolume  = "tailscale-config"
    }
  ]

  secrets = [
    {
      name      = "TS_AUTHKEY",
      valueFrom = "${aws_secretsmanager_secret.authkey[0].arn}:auth_key::"
    },
  ]
  environment      = [for each in local.tailscale_environment : each if each.value != null]
  linux_parameters = { initProcessEnabled = true }
  log_configuration = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.tailscale[0].name
      "awslogs-region"        = var.aws_region
      "awslogs-stream-prefix" = "ecs"
    }
    secretOptions = null
  }
}
module "tailscale_ingress" {
  source  = "cloudposse/ecs-alb-service-task/aws"
  version = "0.76.1"

  vpc_id                             = var.vpc_id
  ecs_cluster_arn                    = var.ecs_cluster_arn
  security_group_ids                 = [aws_security_group.tailscale[0].id]
  security_group_enabled             = false
  subnet_ids                         = var.public_subnet_ids
  assign_public_ip                   = true
  ignore_changes_task_definition     = false
  exec_enabled                       = var.exec_enabled
  desired_count                      = 1
  deployment_maximum_percent         = 100 # we only want one at a time, to prevent tailscale nodes from stepping on eachother
  deployment_minimum_healthy_percent = 0
  task_cpu                           = 1024 # ref https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
  task_memory                        = 2048

  container_definition_json = jsonencode(
    concat(
      [module.tailscale_def.json_map_object],
      var.tailscale_serve_enabled ? [module.tailscale_init_sidecar[0].json_map_object] : []
    )
  )

  bind_mount_volumes = [
    {
      name = "tailscale-config"
    }
  ]
  efs_volumes = [
    {
      host_path = null
      name      = "tailscale-state"
      efs_volume_configuration = [{
        host_path               = null
        file_system_id          = aws_efs_file_system.tailscale_state[0].id
        root_directory          = "/"
        transit_encryption      = "ENABLED"
        transit_encryption_port = var.port_efs_tailscale_state
        authorization_config = [
          {
            access_point_id = aws_efs_access_point.tailscale_state[0].id
            iam             = "DISABLED"
        }]
      }]

    }
  ]

  # the container uses service connect to be able to dynamically reference the keycloak containers by dns "keycloak-web"
  service_connect_configurations = var.service_connect_configurations
  context                        = module.this.context
}


resource "aws_iam_role_policy_attachment" "tailscale_exec" {
  role       = module.tailscale_ingress.task_exec_role_name
  policy_arn = aws_iam_policy.tailscale_exec.arn
}

resource "aws_iam_policy" "tailscale_exec" {
  name   = "${module.this.id}-ecs-execution"
  policy = data.aws_iam_policy_document.tailscale_exec.json
}

data "aws_iam_policy_document" "tailscale_exec" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "kms:Decrypt",
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite",
      "elasticfilesystem:DescribeMountTargets",
      "elasticfilesystem:DescribeFileSystems"

    ]
    resources = [
      aws_secretsmanager_secret.authkey[0].arn,
      var.kms_key_arn,
      aws_efs_file_system.tailscale_state[0].arn
    ]
  }
}

#
resource "aws_iam_role_policy_attachment" "tailscale_task" {
  count      = module.this.enabled ? 1 : 0
  role       = module.tailscale_ingress.task_role_name
  policy_arn = aws_iam_policy.tailscale_task[0].arn
}

resource "aws_iam_policy" "tailscale_task" {
  count  = module.this.enabled ? 1 : 0
  name   = "${module.this.id}-ecs-task"
  policy = data.aws_iam_policy_document.tailscale_task.json
}

data "aws_iam_policy_document" "tailscale_task" {

  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameters",
      "ssm:GetParameter",
      "ssm:PutParameters",
      "ssm:PutParameter",
      "kms:Decrypt",
      "kms:Encrypt",
    ]
    resources = [
      var.kms_key_arn
    ]
  }
}
