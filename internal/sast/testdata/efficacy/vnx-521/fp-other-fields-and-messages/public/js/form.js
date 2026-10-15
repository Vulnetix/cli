$("#profile").validate({
  rules: {
    username: {
      minlength: 3
    },
    zip: { minlength: 5 }
  },
  messages: {
    password: {
      minlength: "Your password must be at least 6 characters long"
    }
  }
});
// if (password.length < 6) the old check was removed
const msg = "password.length < 6 is too weak";
const passwordStrengthMeterBars = 4;
