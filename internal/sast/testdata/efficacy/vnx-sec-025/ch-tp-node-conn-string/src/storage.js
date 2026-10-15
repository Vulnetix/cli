const { BlobServiceClient } = require("@azure/storage-blob");

~>const conn = "DefaultEndpointsProtocol=https;AccountName=prodassets;AccountKey=@@sample:[A-Za-z0-9+/]{86}@@==;EndpointSuffix=core.windows.net";
const client = BlobServiceClient.fromConnectionString(conn);

module.exports = client;
