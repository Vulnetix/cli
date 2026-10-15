// console.log(btoa(password)) is not a way to hide a password
function warn() {
  console.warn("never write console.log(btoa(password)) in production");
}
