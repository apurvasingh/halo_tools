#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'

$outputFile = nil

class TestArgs
  attr_accessor :base_url, :key_id, :key_secret, :cmd, :scanner, :target
  attr_accessor :needs_usage, :verbose

  def initialize()
    @base_url = "https://portal.cloudpassage.com/"
    @key_id = nil
    @key_secret = nil
    @cmd = nil
    @scanner = nil
    @target = nil
    @needs_usage = false
    @verbose = false
  end

  def parse(args)
    allOK = true
    args.each do |arg|
      if (arg.start_with?("--auth="))
        authParam = arg.split('=')[1]
        if (File.file?(authParam) || (! authParam.include?(",")))
          if (! readAuthFile(authParam))
            @cmd = nil
            return
          end
        else
          @key_id, @key_secret = authParam.split(",")
        end
      elsif (arg.start_with?("--url="))
        @base_url = arg.split('=')[1]
      elsif (arg == "--localca")
        ENV['SSL_CERT_FILE'] = File.expand_path(File.dirname(__FILE__)) + "/certs/cacert.pem"
      elsif (arg == "-h") || (arg == "-?")
        @cmd = nil
      elsif (arg == "--allow")
        @cmd = :allow
      elsif (arg == "--block")
        @cmd = :block
      elsif (arg.start_with?("--scanner="))
        @scanner = arg.split('=')[1]
      elsif (arg.start_with?("--target="))
        @target = arg.split('=')[1]
      else
        $stderr.puts "Unrecognized argument: #{arg}"
        allOK = false
        @needs_usage = true
      end
    end
    if (@scanner == nil) || (@target == nil)
      $stderr.puts "Error: Must supply both target and scanner hosts"
      allOK = false
      @needs_usage = true
    end
    if ! allOK
      @cmd = nil
    end
    if (@key_id == nil) || (@key_secret == nil)
      if (! readAuthFile("issues.auth"))
        @cmd = nil
      end
    end
  end

  def readAuthFile(filename)
    if not File.exists? filename
      $stderr.puts "Auth file #{filename} does not exist"
      return false
    end
    File.readlines(filename).each do |line|
      key, value = line.chomp.split("|")
      if ((key != nil) && (value != nil) && ((@key_id == nil) || (@key_secret == nil)))
        @key_id = key
        @key_secret = value
      end
    end
    if @verbose
      puts "AuthFile: id=#{@key_id} secret=#{@key_secret}"
    end
    if @key_id == nil && @key_secret == nil
      $stderr.puts "missing both key ID and secret in auth file"
      false
    elsif @key_id == nil
      $stderr.puts "missing key ID in auth file"
      false
    elsif @key_secret == nil
      $stderr.puts "missing key secret in auth file"
      false
    else
      true
    end
  end

  def usage()
    $stderr.puts "Usage: #{File.basename($0)} [auth-flag] [url-flag] [cmd-flag] [options]"
    $stderr.puts "  where auth-flag can be one of:"
    $stderr.puts "    --auth=<id>,<secret>\tUse provided credentials"
    $stderr.puts "  where url-flag can be one or more of:"
    $stderr.puts "    --url=<url>\t\t\tOverride the base URL to connect to"
    $stderr.puts "    --localca\t\t\tUse local SSL cert file (needed on Windows)"
    $stderr.puts "  where cmd-flag can be one of:"
    $stderr.puts "    --allow\t\t\tAllow the scanning system to access the target"
    $stderr.puts "    --block\t\t\tPrevent the scanning system from accessing the target"
    $stderr.puts "  where options can be one or more of:"
    $stderr.puts "    --scanner=<host>\t\tAddress or hostname of scanner"
    $stderr.puts "    --target=<host>\t\tAddress or hostname being scanned"
  end
end

def matchServer(svr,str)
  return true if (str == svr.hostname)
  return true if (str == svr.connecting_addr)
  svr.interfaces.each { |ifc| return true if (str == ifc.ip_address) }
  return false
end

def makeZone(client,dest)
  zone = findZone(client,dest)
  return zone if (zone != nil)
  # doesn't exist, so create it
  zoneObj = { 'name' => 'scanner source', 'ip_address' => dest }
  zone = Halo::FirewallZones.new zoneObj
  if zone.create client
    return findZone(client,dest)
  end
end

def findZone(client,dest)
  existing_zones = Halo::FirewallZones.all client
  if existing_zones != nil
    existing_zones.each do |zone|
      return zone if (zone.ip_address == dest)
    end
  end
  return nil
end

def findRuleWithZone(client,fwpolicy,zone)
  rule_list = fwpolicy.rules client
  if (rule_list != nil)
    rule_list.each do |rule|
      src = rule.source
      if (src != nil) && (src['type'] == 'FirewallZone') && (src['id'] == zone.id)
        return rule
      end
    end
  end
  return nil
end

def removeFirewallHole(client,fwpolicy,scanner)
  zone = findZone(client,scanner)
  if (zone != nil)
    rule = findRuleWithZone(client,fwpolicy,zone)
    if (rule != nil)
      status = rule.delete client
      puts "Deleting rule (id=#{rule.id}), status=#{status}"
      return true
    end
  end
  puts "AllowScanner rule not found"
  return false
end

def addFirewallHole(client,fwpolicy,scanner)
  zone = makeZone(client,scanner)
  if (zone == nil)
    puts "Unable to create new zone"
    return false
  end
  srcObj = { 'type' => 'FirewallZone', 'id' => zone.id }
  ruleObj = { 'chain' => 'INPUT', 'action' => 'ACCEPT', 'active' => 'true' }
  ruleObj['firewall_source'] = srcObj
  puts "RuleObj=#{ruleObj.to_s}"
  status = fwpolicy.add_rule(client,ruleObj,1) # position=1 is highest priority
  puts "Adding new rule, status=#{status}"
end

cmd_line = TestArgs.new()
cmd_line.parse(ARGV)
if (cmd_line.cmd == nil)
  cmd_line.usage if cmd_line.needs_usage
  exit
end

client = Halo::Client.new
client.base_url = cmd_line.base_url
client.key_id = cmd_line.key_id
client.key_secret = cmd_line.key_secret

begin
  # must call this as it forces retrieval of auth token
  token = client.token
rescue Halo::ConnectionException => conn_err
  $stderr.puts "Connection Error: " + conn_err.error_descr
  exit
rescue Halo::AuthException => api_err
  $stderr.puts "Auth Error: status=#{api_err.http_status} msg=" + api_err.error_msg
  $stderr.puts "            description=" + api_err.error_description
  $stderr.puts "            body=" + api_err.error_body
  exit  
rescue Halo::FailedException => api_err
  $stderr.puts "API Error: status=#{api_err.http_status} msg=" + api_err.error_msg
  $stderr.puts "           description=" + api_err.error_description
  $stderr.puts "           body=" + api_err.error_body
  exit  
end

begin
  matching_fw = nil
  matching_fw_id = nil

  group_list = Halo::ServerGroups.all client
  $stderr.puts "retrieved #{group_list.length} server groups"
  policy_list = Halo::FirewallPolicies.all client
  $stderr.puts "retrieved #{policy_list.length} firewall policies"

  group_list.each do |gr|
    member_list = gr.servers client
    if (member_list != nil) && (member_list.length > 0)
      member_list.each do |svr|
        if (matchServer(svr,cmd_line.target))
          puts "Group: #{gr.to_s}"
          puts "Server: #{svr.to_s}"
          puts "  platform=#{svr.platform}"
          if (svr.platform == "windows")
            matching_fw_id = gr.windows_firewall_policy_id
          else
            matching_fw_id = gr.linux_firewall_policy_id
          end
        end
      end
    end
  end

  if (matching_fw_id != nil)
    policy_list.each do |fw|
      matching_fw = fw if (fw.id == matching_fw_id)
    end
  end
  if (matching_fw != nil)
    puts matching_fw.to_s
    puts " "
    if (cmd_line.cmd == :allow)
      puts "changing fw policy #{matching_fw.name} to allow #{cmd_line.scanner}"
      addFirewallHole(client,matching_fw,cmd_line.scanner)
    elsif (cmd_line.cmd == :block)
      puts "changing fw policy #{matching_fw.name} to block #{cmd_line.scanner}"
      removeFirewallHole(client,matching_fw,cmd_line.scanner)
    else
      puts "unknown command: specify --allow or --block"
    end
  else
    $stderr.puts "Unable to find appropriate firewall policy"
  end

rescue Halo::ConnectionException => conn_err
  $stderr.puts "Connection Error: " + conn_err.error_descr
  exit
rescue Halo::AuthException => api_err
  $stderr.puts "Auth Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  $stderr.puts "            description=#{api_err.error_description}"
  $stderr.puts "            body=#{api_err.error_body}"
  exit  
rescue Halo::FailedException => api_err
  $stderr.puts "API Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  $stderr.puts "           description=#{api_err.error_description}"
  $stderr.puts "           request_url=#{api_err.url}"
  $stderr.puts "           body=#{api_err.error_body}"
  exit
ensure
  $outputFile.close() unless $outputFile == nil
end
