const express = require('express');
const security = require('../lib/security');
const app = express();

app.use(security.updateAuthenticatedUsers());
app.use('/rest/basket', security.isAuthorized());
~>app.get('/rest/admin/application-configuration', utils.asyncHandler(readConfiguration()));
app.get('/rest/basket/admin-view', utils.asyncHandler(basket()));
