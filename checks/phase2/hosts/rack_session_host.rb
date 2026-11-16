# Minimal host application around Rack::Session::Pool (rack-session) at a pinned commit.
# It speaks the endpoint contract of the SessTrace "profile" operation: /login, /profile, /logout,
# plus /slow_profile, which reads the user at once and answers after <slow seconds>.
# Usage: ruby rack_session_host.rb <path of the checked-out library> <port> <slow seconds>
lib, port, slow = ARGV[0], Integer(ARGV[1]), Float(ARGV[2])
$LOAD_PATH.unshift(File.join(lib, 'lib')) # the library is loaded from the checkout
require 'json'
require 'rack'
require 'rack/session/pool'
require 'rack/session/version'
require 'rackup'
require 'webrick'

$stdout.sync = true
$stderr.sync = true
puts "rack #{Gem.loaded_specs['rack']&.version}, rack-session #{Rack::Session::VERSION}"
puts "write_session defined at #{Rack::Session::Pool.instance_method(:write_session).source_location.join(':')}"

def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC).round(3)
def json(code, obj) = [code, { 'content-type' => 'application/json' }, [JSON.generate(obj)]]

app = lambda do |env|
  req = Rack::Request.new(env)
  session = env['rack.session']
  case req.path_info
  when '/ready' then json(200, ok: true)
  when '/login'
    user = req.params['user'].to_s
    next json(400, error: 'invalid_request') unless %w[alice bob].include?(user)
    session['user'] = user
    json(200, logged_in: true)
  when '/profile', '/slow_profile'
    user = session['user'] # loads the session now
    if req.path_info == '/slow_profile'
      puts "#{clock} slow_profile loaded the session (user present: #{!user.nil?})"
      sleep slow
      puts "#{clock} slow_profile answers"
    end
    user ? json(200, sub: user, rp: 'RP1') : json(401, error: 'no_session')
  when '/logout'
    # as in the maintainer regression test/spec_session_pool.rb: delete the user and renew the id
    session.delete('user')
    session.options[:renew] = true
    puts "#{clock} logout"
    json(200, logged_out: true)
  else json(404, error: 'not_found')
  end
end

server_app = Rack::Session::Pool.new(app, key: 'sid')
puts 'READY'
Rackup::Handler::WEBrick.run(server_app, Host: '127.0.0.1', Port: port, AccessLog: [])
