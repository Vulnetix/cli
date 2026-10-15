userSchema.pre("save", async function () {
  this.password = await bcrypt.hash(this.password, 12);
});
