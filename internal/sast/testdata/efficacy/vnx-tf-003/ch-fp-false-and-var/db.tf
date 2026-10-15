resource "aws_db_instance" "a" {
  identifier          = "a"
  publicly_accessible = false
}

resource "aws_db_instance" "b" {
  identifier          = "b"
  publicly_accessible = var.db_public
  # publicly_accessible = true
}

variable "db_public" {
  type    = bool
  default = true
}
