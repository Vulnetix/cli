resource "aws_instance" "app" {
  ami           = "ami-0abc"
  instance_type = "t3.large"

  root_block_device {
    volume_size = 40
~>    encrypted   = false
  }
}
