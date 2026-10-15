router.beforeEach((to, from, next) => {
~>  if (to.meta.requiresAuth && !localStorage.isLoggedIn) {
    next('/login');
  } else {
    next();
  }
});
