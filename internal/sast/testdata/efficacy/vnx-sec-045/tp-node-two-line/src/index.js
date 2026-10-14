const { Client, GatewayIntentBits } = require('discord.js');
~>const TOKEN = '@@sample:MT[AEIMQUYcgk][w-z0-5](?:[MNO][DTjz][AEIMQUYcgk][w-z0-5]){5}[MNO][AQgw]\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{38}@@';
const client = new Client({ intents: [GatewayIntentBits.Guilds] });
client.login(TOKEN);
