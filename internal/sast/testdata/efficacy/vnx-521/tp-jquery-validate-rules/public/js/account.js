$(function () {
  $("#signup").validate({
    rules: {
      "user[password]": {
        required: true,
~>        minlength: 6
      },
      email: {
        required: true,
        minlength: 3
      }
    },
    messages: {
      "user[password]": {
        minlength: "Your password must be at least 6 characters long"
      }
    }
  });
});

const UserSchema = new mongoose.Schema({
  name: { type: String, minlength: 2 },
~>  password: { type: String, required: true, minlength: 5 },
});
