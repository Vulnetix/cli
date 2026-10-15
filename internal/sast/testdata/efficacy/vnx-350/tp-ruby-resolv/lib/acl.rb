require "resolv"

def trusted?(ip)
~>  name = Resolv.getname(ip)
  name.end_with?(".example.com")
end
