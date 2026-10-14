object Auth {
  def login(user: String, password: String): Unit = {
~>    logger.info(s"login $user $password")
  }
}
