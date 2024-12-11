<!-- markdownlint-disable -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.0.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.6.3 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | >= 4.0.6 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.0.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_label_log_group_tailscale"></a> [label\_log\_group\_tailscale](#module\_label\_log\_group\_tailscale) | cloudposse/label/null | 0.25.0 |
| <a name="module_label_log_group_tailscale_init"></a> [label\_log\_group\_tailscale\_init](#module\_label\_log\_group\_tailscale\_init) | cloudposse/label/null | 0.25.0 |
| <a name="module_label_ssm_params_tailscale"></a> [label\_ssm\_params\_tailscale](#module\_label\_ssm\_params\_tailscale) | cloudposse/label/null | 0.25.0 |
| <a name="module_label_ts"></a> [label\_ts](#module\_label\_ts) | cloudposse/label/null | 0.25.0 |
| <a name="module_tailscale_def"></a> [tailscale\_def](#module\_tailscale\_def) | cloudposse/ecs-container-definition/aws | 0.61.1 |
| <a name="module_tailscale_ingress"></a> [tailscale\_ingress](#module\_tailscale\_ingress) | cloudposse/ecs-alb-service-task/aws | 0.76.1 |
| <a name="module_tailscale_init_sidecar"></a> [tailscale\_init\_sidecar](#module\_tailscale\_init\_sidecar) | cloudposse/ecs-container-definition/aws | 0.61.1 |
| <a name="module_this"></a> [this](#module\_this) | cloudposse/label/null | 0.25.0 |
| <a name="module_ts_rotate"></a> [ts\_rotate](#module\_ts\_rotate) | guardianproject-ops/lambda-secrets-manager-tailscale/aws | 0.0.1 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.tailscale](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.tailscale_init](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_efs_access_point.tailscale_state](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_access_point) | resource |
| [aws_efs_file_system.tailscale_state](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system) | resource |
| [aws_efs_mount_target.tailscale_state](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_mount_target) | resource |
| [aws_iam_policy.tailscale_exec](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.tailscale_task](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role_policy_attachment.tailscale_exec](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.tailscale_task](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_secretsmanager_secret.authkey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret_rotation.authkey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation) | resource |
| [aws_secretsmanager_secret_version.authkey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version) | resource |
| [aws_security_group.tailscale](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.tailscale_to_efs_state](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_egress_rule.tailscale_egress_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_egress_rule.tailscale_to_efs_state_egress_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.tailscale_tailscale](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.tailscale_to_efs_state_tailscale](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_iam_policy_document.tailscale_exec](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.tailscale_task](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_additional_tag_map"></a> [additional\_tag\_map](#input\_additional\_tag\_map) | Additional key-value pairs to add to each map in `tags_as_list_of_maps`. Not added to `tags` or `id`.<br/>This is for some rare cases where resources want additional configuration of tags<br/>and therefore take a list of maps with tag key, value, and additional configuration. | `map(string)` | `{}` | no |
| <a name="input_attributes"></a> [attributes](#input\_attributes) | ID element. Additional attributes (e.g. `workers` or `cluster`) to add to `id`,<br/>in the order they appear in the list. New attributes are appended to the<br/>end of the list. The elements of the list are joined by the `delimiter`<br/>and treated as a single ID element. | `list(string)` | `[]` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | n/a | `string` | n/a | yes |
| <a name="input_context"></a> [context](#input\_context) | Single object for setting entire context at once.<br/>See description of individual variables for details.<br/>Leave string and numeric variables as `null` to use default value.<br/>Individual variable settings (non-null) override settings in context object,<br/>except for attributes, tags, and additional\_tag\_map, which are merged. | `any` | <pre>{<br/>  "additional_tag_map": {},<br/>  "attributes": [],<br/>  "delimiter": null,<br/>  "descriptor_formats": {},<br/>  "enabled": true,<br/>  "environment": null,<br/>  "id_length_limit": null,<br/>  "label_key_case": null,<br/>  "label_order": [],<br/>  "label_value_case": null,<br/>  "labels_as_tags": [<br/>    "unset"<br/>  ],<br/>  "name": null,<br/>  "namespace": null,<br/>  "regex_replace_chars": null,<br/>  "stage": null,<br/>  "tags": {},<br/>  "tenant": null<br/>}</pre> | no |
| <a name="input_delimiter"></a> [delimiter](#input\_delimiter) | Delimiter to be used between ID elements.<br/>Defaults to `-` (hyphen). Set to `""` to use no delimiter at all. | `string` | `null` | no |
| <a name="input_descriptor_formats"></a> [descriptor\_formats](#input\_descriptor\_formats) | Describe additional descriptors to be output in the `descriptors` output map.<br/>Map of maps. Keys are names of descriptors. Values are maps of the form<br/>`{<br/>   format = string<br/>   labels = list(string)<br/>}`<br/>(Type is `any` so the map values can later be enhanced to provide additional options.)<br/>`format` is a Terraform format string to be passed to the `format()` function.<br/>`labels` is a list of labels, in order, to pass to `format()` function.<br/>Label values will be normalized before being passed to `format()` so they will be<br/>identical to how they appear in `id`.<br/>Default is `{}` (`descriptors` output will be empty). | `any` | `{}` | no |
| <a name="input_ecs_cluster_arn"></a> [ecs\_cluster\_arn](#input\_ecs\_cluster\_arn) | n/a | `string` | n/a | yes |
| <a name="input_enabled"></a> [enabled](#input\_enabled) | Set to false to prevent the module from creating any resources | `bool` | `null` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | ID element. Usually used for region e.g. 'uw2', 'us-west-2', OR role 'prod', 'staging', 'dev', 'UAT' | `string` | `null` | no |
| <a name="input_exec_enabled"></a> [exec\_enabled](#input\_exec\_enabled) | Specifies whether to enable Amazon ECS Exec for the tasks within the service | `bool` | `false` | no |
| <a name="input_id_length_limit"></a> [id\_length\_limit](#input\_id\_length\_limit) | Limit `id` to this many characters (minimum 6).<br/>Set to `0` for unlimited length.<br/>Set to `null` for keep the existing setting, which defaults to `0`.<br/>Does not affect `id_full`. | `number` | `null` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | Used for transit and tailscale state encryption | `string` | n/a | yes |
| <a name="input_label_key_case"></a> [label\_key\_case](#input\_label\_key\_case) | Controls the letter case of the `tags` keys (label names) for tags generated by this module.<br/>Does not affect keys of tags passed in via the `tags` input.<br/>Possible values: `lower`, `title`, `upper`.<br/>Default value: `title`. | `string` | `null` | no |
| <a name="input_label_order"></a> [label\_order](#input\_label\_order) | The order in which the labels (ID elements) appear in the `id`.<br/>Defaults to ["namespace", "environment", "stage", "name", "attributes"].<br/>You can omit any of the 6 labels ("tenant" is the 6th), but at least one must be present. | `list(string)` | `null` | no |
| <a name="input_label_value_case"></a> [label\_value\_case](#input\_label\_value\_case) | Controls the letter case of ID elements (labels) as included in `id`,<br/>set as tag values, and output by this module individually.<br/>Does not affect values of tags passed in via the `tags` input.<br/>Possible values: `lower`, `title`, `upper` and `none` (no transformation).<br/>Set this to `title` and set `delimiter` to `""` to yield Pascal Case IDs.<br/>Default value: `lower`. | `string` | `null` | no |
| <a name="input_labels_as_tags"></a> [labels\_as\_tags](#input\_labels\_as\_tags) | Set of labels (ID elements) to include as tags in the `tags` output.<br/>Default is to include all labels.<br/>Tags with empty values will not be included in the `tags` output.<br/>Set to `[]` to suppress all generated tags.<br/>**Notes:**<br/>  The value of the `name` tag, if included, will be the `id`, not the `name`.<br/>  Unlike other `null-label` inputs, the initial setting of `labels_as_tags` cannot be<br/>  changed in later chained modules. Attempts to change it will be silently ignored. | `set(string)` | <pre>[<br/>  "default"<br/>]</pre> | no |
| <a name="input_log_group_retention_in_days"></a> [log\_group\_retention\_in\_days](#input\_log\_group\_retention\_in\_days) | The number in days that cloudwatch logs will be retained. | `number` | `30` | no |
| <a name="input_name"></a> [name](#input\_name) | ID element. Usually the component or solution name, e.g. 'app' or 'jenkins'.<br/>This is the only ID element not also included as a `tag`.<br/>The "name" tag is set to the full `id` string. There is no tag with the value of the `name` input. | `string` | `null` | no |
| <a name="input_namespace"></a> [namespace](#input\_namespace) | ID element. Usually an abbreviation of your organization name, e.g. 'eg' or 'cp', to help ensure generated IDs are globally unique | `string` | `null` | no |
| <a name="input_port_efs_tailscale_state"></a> [port\_efs\_tailscale\_state](#input\_port\_efs\_tailscale\_state) | The port number at which the tailscale state efs mount is available | `number` | `2049` | no |
| <a name="input_port_tailscale_healthcheck"></a> [port\_tailscale\_healthcheck](#input\_port\_tailscale\_healthcheck) | The port number for Tailscale health check endpoint | `number` | `7801` | no |
| <a name="input_private_subnet_ids"></a> [private\_subnet\_ids](#input\_private\_subnet\_ids) | The ids for the private subnets that EFS will be deployed into | `list(string)` | n/a | yes |
| <a name="input_public_subnet_ids"></a> [public\_subnet\_ids](#input\_public\_subnet\_ids) | The ids for the public subnets that ECS will be deployed into | `list(string)` | n/a | yes |
| <a name="input_regex_replace_chars"></a> [regex\_replace\_chars](#input\_regex\_replace\_chars) | Terraform regular expression (regex) string.<br/>Characters matching the regex will be removed from the ID elements.<br/>If not set, `"/[^a-zA-Z0-9-]/"` is used to remove all characters other than hyphens, letters and digits. | `string` | `null` | no |
| <a name="input_service_connect_configurations"></a> [service\_connect\_configurations](#input\_service\_connect\_configurations) | The list of Service Connect configurations.<br/>See `service_connect_configuration` docs https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#service_connect_configuration | <pre>list(object({<br/>    enabled   = bool<br/>    namespace = optional(string, null)<br/>    log_configuration = optional(object({<br/>      log_driver = string<br/>      options    = optional(map(string), null)<br/>      secret_option = optional(list(object({<br/>        name       = string<br/>        value_from = string<br/>      })), [])<br/>    }), null)<br/>    service = optional(list(object({<br/>      client_alias = list(object({<br/>        dns_name = string<br/>        port     = number<br/>      }))<br/>      timeout = optional(list(object({<br/>        idle_timeout_seconds        = optional(number, null)<br/>        per_request_timeout_seconds = optional(number, null)<br/>      })), [])<br/>      tls = optional(list(object({<br/>        kms_key  = optional(string, null)<br/>        role_arn = optional(string, null)<br/>        issuer_cert_authority = object({<br/>          aws_pca_authority_arn = string<br/>        })<br/>      })), [])<br/>      discovery_name        = optional(string, null)<br/>      ingress_port_override = optional(number, null)<br/>      port_name             = string<br/>    })), [])<br/>  }))</pre> | `[]` | no |
| <a name="input_stage"></a> [stage](#input\_stage) | ID element. Usually used to indicate role, e.g. 'prod', 'staging', 'source', 'build', 'test', 'deploy', 'release' | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Additional tags (e.g. `{'BusinessUnit': 'XYZ'}`).<br/>Neither the tag keys nor the tag values will be modified by this module. | `map(string)` | `{}` | no |
| <a name="input_tailscale_accept_dns"></a> [tailscale\_accept\_dns](#input\_tailscale\_accept\_dns) | TS\_ACCEPT\_DNS Accept DNS configuration from the admin console. Not accepted by default. | `bool` | `false` | no |
| <a name="input_tailscale_client_id"></a> [tailscale\_client\_id](#input\_tailscale\_client\_id) | The OIDC client id for tailscale that has permissions to create auth keys with the `tailscale_tags_keycloak` tags | `string` | n/a | yes |
| <a name="input_tailscale_client_secret"></a> [tailscale\_client\_secret](#input\_tailscale\_client\_secret) | The OIDC client secret paired with `tailscale_client_id` | `string` | n/a | yes |
| <a name="input_tailscale_container_image"></a> [tailscale\_container\_image](#input\_tailscale\_container\_image) | The fully qualified container image for tailscale. | `string` | `"ghcr.io/tailscale/tailscale:stable"` | no |
| <a name="input_tailscale_extra_args"></a> [tailscale\_extra\_args](#input\_tailscale\_extra\_args) | n/a | `list(string)` | `[]` | no |
| <a name="input_tailscale_hostname"></a> [tailscale\_hostname](#input\_tailscale\_hostname) | The hostname for this tailscale device, will default to to the context id | `string` | `null` | no |
| <a name="input_tailscale_routes"></a> [tailscale\_routes](#input\_tailscale\_routes) | TS\_ROUTES Advertise subnet routes. This is equivalent to tailscale set --advertise-routes=. | `string` | `null` | no |
| <a name="input_tailscale_serve_enabled"></a> [tailscale\_serve\_enabled](#input\_tailscale\_serve\_enabled) | Whether to Serve | `bool` | `false` | no |
| <a name="input_tailscale_serve_upstream_url"></a> [tailscale\_serve\_upstream\_url](#input\_tailscale\_serve\_upstream\_url) | The url to serve with tailscale serve | `string` | `null` | no |
| <a name="input_tailscale_ssh_enabled"></a> [tailscale\_ssh\_enabled](#input\_tailscale\_ssh\_enabled) | n/a | `bool` | `true` | no |
| <a name="input_tailscale_tags_keycloak"></a> [tailscale\_tags\_keycloak](#input\_tailscale\_tags\_keycloak) | The list of tags that will be assigned to tailscale node created by this stack. | `list(string)` | n/a | yes |
| <a name="input_tailscale_tailnet"></a> [tailscale\_tailnet](#input\_tailscale\_tailnet) | description = The tailnet domain (or "organization's domain") for your tailscale tailnet, this s found under Settings > General > Organization | `string` | n/a | yes |
| <a name="input_tailscaled_extra_args"></a> [tailscaled\_extra\_args](#input\_tailscaled\_extra\_args) | n/a | `list(string)` | `null` | no |
| <a name="input_tenant"></a> [tenant](#input\_tenant) | ID element \_(Rarely used, not included by default)\_. A customer identifier, indicating who this instance of a resource is for | `string` | `null` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | n/a | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cloudwatch_log_group_arn_tailscale"></a> [cloudwatch\_log\_group\_arn\_tailscale](#output\_cloudwatch\_log\_group\_arn\_tailscale) | Cloudwatch log group ARN for tailscale |
| <a name="output_cloudwatch_log_group_name_tailscale"></a> [cloudwatch\_log\_group\_name\_tailscale](#output\_cloudwatch\_log\_group\_name\_tailscale) | Cloudwatch log group name for tailscale |
| <a name="output_cloudwatch_log_group_tailscale"></a> [cloudwatch\_log\_group\_tailscale](#output\_cloudwatch\_log\_group\_tailscale) | All outputs from `aws_cloudwatch_log_group.tailscale` |
| <a name="output_efs_file_system_id"></a> [efs\_file\_system\_id](#output\_efs\_file\_system\_id) | n/a |
| <a name="output_efs_security_group_id"></a> [efs\_security\_group\_id](#output\_efs\_security\_group\_id) | n/a |
| <a name="output_secrets_manager_secret_authkey_arn"></a> [secrets\_manager\_secret\_authkey\_arn](#output\_secrets\_manager\_secret\_authkey\_arn) | n/a |
| <a name="output_secrets_manager_secret_authkey_id"></a> [secrets\_manager\_secret\_authkey\_id](#output\_secrets\_manager\_secret\_authkey\_id) | n/a |
| <a name="output_security_group_id"></a> [security\_group\_id](#output\_security\_group\_id) | n/a |
<!-- markdownlint-restore -->