router.post("/signup", async (req, res) => {
~>  const user = new User({ email: req.body.email, password: req.body.password });
  await user.save();
  const { username, password } = req.body;
~>  await Account.create({ username, password: password });
~>  res.cookie("password", req.body.password, { httpOnly: true });
});

function remember(form) {
  const password = form.password.value;
~>  localStorage.setItem("password", password);
~>  window.sessionStorage.setItem('user_password', form.password.value);
}
