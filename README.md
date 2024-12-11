
<!-- markdownlint-disable -->
# terraform-aws-ecs-service-tailscale


<!-- markdownlint-restore -->

<!-- [![README Header][readme_header_img]][readme_header_link] -->

[![The Guardian][logo]][website]

<!--




  ** DO NOT EDIT THIS FILE
  **
  ** This file was automatically generated by the `build-harness`.
  ** 1) Make all changes to `README.yaml`
  ** 2) Run `make init` (you only need to do this once)
  ** 3) Run`make readme` to rebuild this file.
  **
  ** (We maintain HUNDREDS of open source projects. This is how we maintain our sanity.)
  **





-->

Terraform module for deploying tailscale to an ECS cluster

---






It's 100% Open Source and licensed under the [GNU General Public License](LICENSE).









## Introduction


This is a module for deploying tailscale as a standalone ECS service. It features:

  * A lambda that rotates the auth key automatically using AWS Secrets Manager
  * Ability to `tailscale serve` an upstream in your cluster using AWS Service Connect
  * Automatic state persistence with AWS EFS



## Usage


**IMPORTANT:** We do not pin modules to versions in our examples because of the
difficulty of keeping the versions in the documentation in sync with the latest released versions.
We highly recommend that in your code you pin the version to the exact version you are
using so that your infrastructure remains stable, and update versions in a
systematic way so that they do not catch you by surprise.

Also, because of a bug in the Terraform registry ([hashicorp/terraform#21417](https://github.com/hashicorp/terraform/issues/21417)),
the registry shows many of our inputs as required when in fact they are optional.
The table below correctly indicates which inputs are required.



```terraform
module "db" {
  source                              = "guardianproject-ops/ecs-service-tailscale/aws"
  context = module.label_tailscale.context
  vpc_id                       = var.vpc_id
  kms_key_arn                  = local.kms_key_arn
  private_subnet_ids           = var.private_subnet_ids
  public_subnet_ids            = var.public_subnet_ids
  tailscale_container_image    = var.tailscale_container_image
  tailscale_serve_enabled      = true
  tailscale_serve_upstream_url = "https+insecure://keycloak-web:${local.port_keycloak_web}"
  aws_region                   = local.region
  tailscale_tags_keycloak      = var.tailscale_tags_keycloak
  tailscale_tailnet            = var.tailscale_tailnet
  tailscale_client_id          = var.tailscale_client_id
  tailscale_client_secret      = var.tailscale_client_secret
  ecs_cluster_arn              = module.ecs_cluster.arn
  tailscale_hostname           = "my-ts-task"
  service_connect_configurations = [{
    enabled   = true
    namespace = aws_service_discovery_http_namespace.this[0].arn
    service   = []
  }]
}
```






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




## Help

**Got a question?** We got answers.

File a GitLab [issue](https://gitlab.com/guardianproject-ops/terraform-aws-ecs-service-tailscale/-/issues), send us an [email][email] or join our [Matrix Community][matrix].

## Matrix Community

[![Matrix badge](https://img.shields.io/badge/Matrix-%23guardianproject%3Amatrix.org-blueviolet)][matrix]

Join our [Open Source Community][matrix] on Matrix. It's **FREE** for everyone!
This is the best place to talk shop, ask questions, solicit feedback, and work
together as a community to build on our open source code.

## Contributing

### Bug Reports & Feature Requests

Please use the [issue tracker](https://gitlab.com/guardianproject-ops/terraform-aws-ecs-service-tailscale/-/issues) to report any bugs or file feature requests.

### Developing

If you are interested in being a contributor and want to get involved in developing this project or help out with our other projects, we would love to hear from you! Shoot us an [email][email].

In general, PRs are welcome. We follow the typical "fork-and-pull" Git workflow.

 1. **Fork** the repo on GitLab
 2. **Clone** the project to your own machine
 3. **Commit** changes to your own branch
 4. **Push** your work back up to your fork
 5. Submit a **Pull Request** so that we can review your changes

**NOTE:** Be sure to merge the latest changes from "upstream" before making a pull request!


## Copyright

Copyright © 2021-2024 The Guardian Project










## License

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

```text
GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```






## Trademarks

All other trademarks referenced herein are the property of their respective owners.

## About

This project is maintained by [The Guardian Project][website].

[![The Guardian Project][logo]][website]

We're a [collective of designers, developers, and ops][website] folk focused on useable
privacy and security with a focus on digital human rights and humanitarian projects.

Everything we do is 100% FOSS.

Follow us on [Mastodon][mastodon] or [twitter][twitter], [apply for a job][join], or
[partner with us][partner].

We offer [paid support][contact] on all of our projects.

Check out [our other DevOps projects][gitlab] or our [entire other set of
projects][nonops] related to privacy and security related software, or [hire
us][website] to get support with using our projects.


## Contributors

<!-- markdownlint-disable -->
|  [![Abel Luck][abelxluck_avatar]][abelxluck_homepage]<br/>[Abel Luck][abelxluck_homepage] |
|---|
<!-- markdownlint-restore -->

  [abelxluck_homepage]: https://gitlab.com/abelxluck

  [abelxluck_avatar]: https://secure.gravatar.com/avatar/0f605397e0ead93a68e1be26dc26481a?s=200&amp;d=identicon


<!-- markdownlint-disable -->
  [website]: https://guardianproject.info/?utm_source=gitlab&utm_medium=readme&utm_campaign=guardianproject-ops/terraform-aws-ecs-service-tailscale&utm_content=website
  [gitlab]: https://www.gitlab.com/guardianproject-ops
  [contact]: https://guardianproject.info/contact/
  [matrix]: https://matrix.to/#/%23guardianproject:matrix.org
  [readme_header_img]: https://gitlab.com/guardianproject/guardianprojectpublic/-/raw/master/Graphics/GuardianProject/pngs/logo-color-w256.png
  [readme_header_link]: https://guardianproject.info?utm_source=gitlab&utm_medium=readme&utm_campaign=guardianproject-ops/terraform-aws-ecs-service-tailscale&utm_content=readme_header_link
  [readme_commercial_support_img]: https://www.sr2.uk/readme/paid-support.png
  [readme_commercial_support_link]: https://www.sr2.uk/?utm_source=gitlab&utm_medium=readme&utm_campaign=guardianproject-ops/terraform-aws-ecs-service-tailscale&utm_content=readme_commercial_support_link
  [partner]: https://guardianproject.info/how-you-can-work-with-us/
  [nonops]: https://gitlab.com/guardianproject
  [mastodon]: https://social.librem.one/@guardianproject
  [twitter]: https://twitter.com/guardianproject
  [email]: mailto:support@guardianproject.info
  [join_email]: mailto:jobs@guardianproject.info
  [join]: https://guardianproject.info/contact/join/
  [logo_square]: https://assets.gitlab-static.net/uploads/-/system/group/avatar/3262938/guardianproject.png?width=88
  [logo]: https://gitlab.com/guardianproject/guardianprojectpublic/-/raw/master/Graphics/GuardianProject/pngs/logo-color-w256.png
  [logo_black]: https://gitlab.com/guardianproject/guardianprojectpublic/-/raw/master/Graphics/GuardianProject/pngs/logo-black-w256.png
  [cdr]: https://digiresilience.org
  [cdr-tech]: https://digiresilience.org/tech/
<!-- markdownlint-restore -->
