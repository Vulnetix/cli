require "slack-ruby-client"

~>client = Slack::Web::Client.new(token: 'xoxp-@@sample:[0-9]{12}-[0-9]{12}-[0-9]{13}-[a-f0-9]{32}@@')
client.chat_postMessage(channel: "#ops", text: "deployed")
