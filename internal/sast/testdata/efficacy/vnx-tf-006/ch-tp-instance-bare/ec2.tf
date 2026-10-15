~>resource "aws_instance" "jump" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.nano"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.jump.id]

  root_block_device {
    encrypted = true
  }
}

resource "aws_eip" "jump" {
  instance = aws_instance.jump.id
}
