require 'net/http'

~>uri = URI.parse("http://billing.saas-vendor.com/charge")
~>res = Net::HTTP.post_form(URI("http://billing.saas-vendor.com/refund"), params)
~>SERVICE_HOST = "http://billing.saas-vendor.com"
