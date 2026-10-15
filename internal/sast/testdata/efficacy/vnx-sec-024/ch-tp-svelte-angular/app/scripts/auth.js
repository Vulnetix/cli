angular.module("app").service("Auth", function ($window, $http) {
  this.login = function (creds) {
    return $http.post("/api/login", creds).then(function (res) {
~>      $window.localStorage.setItem(
        "refresh_token",
        res.data.refresh_token
      );
    });
  };
});
