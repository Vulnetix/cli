# use Rack::Session::Cookie, secret: 'Hn3Kq8Zr2Lw9Vx4Bt7Mp1Cy6Df5Gs0Aj'
use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET")
