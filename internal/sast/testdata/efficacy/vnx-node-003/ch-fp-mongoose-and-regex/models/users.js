const mongoose = require("mongoose");
const { exec } = require("child_process");

async function findByName(name) {
  const users = await mongoose.model("User").find({ name: name }).exec();
  const match = new RegExp("^" + name).exec(users[0].email + "@");
  const q = User.findOne({ email: name + "@example.com" }).exec();
  return { users, match, q };
}

exec("git rev-parse --short HEAD", (err, sha) => console.log(sha));
module.exports = { findByName };
