var exec = require("child_process").exec;

module.exports = function (grunt) {
  grunt.registerTask("db-reset", function () {
    var env = grunt.option("env") || "development";
    var cmd = "NODE_ENV=" + env + " ";
~>    exec(
      cmd + "node scripts/db-reset.js",
      this.async()
    );
  });
};
