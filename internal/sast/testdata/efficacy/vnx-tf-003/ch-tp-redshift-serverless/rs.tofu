resource "aws_redshiftserverless_namespace" "ns" {
  namespace_name = "analytics"
}

resource "aws_redshiftserverless_workgroup" "wg" {
  namespace_name = aws_redshiftserverless_namespace.ns.namespace_name
  workgroup_name = "analytics"
  base_capacity  = 32
~>  publicly_accessible = true
}
