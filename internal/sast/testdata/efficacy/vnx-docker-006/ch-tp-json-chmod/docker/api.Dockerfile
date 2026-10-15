FROM node:20.15.1
~>ADD --chmod=755 ["bin/start", "/usr/local/bin/start"]
CMD ["start"]
