import errorHandler from 'errorhandler';

export function setup(app) {
  app.use(router);
~>  app.use(errorHandler());
}
