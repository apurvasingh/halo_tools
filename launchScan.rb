#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'

class CmdArgs
  attr_accessor :base_url, :key_id, :key_secret, :cmd, :arg, :verbose, :url, :nopoll
  attr_accessor :scantype, :group_name, :display_issues, :get_status, :starting, :delay, :firstx
  attr_accessor :listonly, :roundrobin, :instance_name_delimiter

  def initialize()
    @base_url = "https://portal.cloudpassage.com/"
    @key_id = "05266dad"
    @key_secret = "03f7ce883627f654cc877f67c9d61393"
    @cmd = "listing"
    @arg = nil
    @url = nil
    @group_name = nil
    @scantype = nil
    @verbose = false
    @display_issues = false
    @get_status = false
    @starting = nil
    @nopoll = false
    @delay = nil
    @firstx = nil
    @listonly = false
    @roundrobin = false
    @instance_name_delimiter = '_'
  end

  def parse(args)
    ok = true
    args.each do |arg|
      if (arg.start_with?("--auth="))
        argarg, filename = arg.split("=")
        readAuthFile(filename)
      elsif (arg == "-v")
        @verbose = true
      elsif (arg == "-?") || (arg == "-h")
        usage
        exit
      elsif (arg.start_with?("--servergroup="))
        argarg, @group_name = arg.split("=")
      elsif (arg.start_with?("--scantype="))
        argarg, @scantype = arg.split("=")
        # puts "Scan type: #{scantype}"
      elsif (arg.start_with?("--url="))
        argarg, @url = arg.split("=")
      elsif (arg.start_with?("--starting="))
        argarg, @starting = arg.split("=")
      elsif (arg.start_with?("--base="))
        argarg, @base_url = arg.split("=")
      elsif (arg == "--issues")
        @display_issues = true
      elsif (arg == "--scanstatus")
        @get_status = true
      elsif (arg == "--nopoll")
        @nopoll = true
      elsif (arg == "--listonly")
        @listonly = true
      elsif (arg == "--roundrobin") || (arg == "--loadbalance")
        @roundrobin = true
      elsif (arg.start_with?("--numofservers="))
        argarg, tmp = arg.split("=")
        @firstx = tmp.to_i
        if @firstx == 0
          puts "Illegal number of servers value: #{tmp}"
          exit
        end
      elsif (arg.start_with?("--interval="))
        argarg, tmp = arg.split("=")
        @delay = tmp.to_i
        if @delay == 0
          puts "Illegal scan start delay value: #{tmp}"
          exit
        end
      elsif (arg == "--localca")
        ENV['SSL_CERT_FILE'] = File.expand_path(File.dirname(__FILE__)) + "/certs/cacert.pem"
      else
        puts "Unrecognized argument: #{arg}"
        ok = false
      end
    end
    exit if (! ok)
  end

  def usage()
    puts "Usage: #{File.basename($0)} [flag]"
    puts "  where flag can be one of:"
    puts "    --auth=<file>\t\tRead auth info from <file>"
    puts "    --servergroup=<groupname>\tSpecify name of server group to scan"
    puts "    --scantype=<type>\t\tSpecify type of scan (sca, svm, etc.)"
    puts "    --scanstatus\t\tRequest status of scans on one or all servers"
    puts "    --url=<url>\t\t\tCheck on a previously issued scan"
    puts "    --starting=<when>\t\tOnly get status for scans after when (ISO-8601 format)"
    puts "    --base=<url>\t\tOverride base URL (normally #{@base_url})"
    puts "    --issues\t\t\tDisplay issues found by scan"
    puts "    --nopoll\t\t\tDon't poll for scan completion after launching scans"
    puts "    --interval=<secs>\t\tDelay between scan launches (in seconds)"
    puts "    --numofservers=<n>\t\tMaximum number of servers to launch scans on"
    puts "    --localca\t\t\tUse local SSL cert file (needed on Windows)"
    puts "    --roundrobin\t\tBalance the load evenly across EC2 instances"
    puts "    -v\t\t\t\tVerbose output"
  end

  def readAuthFile(filename)
    if not File.exists? filename
      puts "Auth file #{filename} does not exist"
      return false
    end
    File.readlines(filename).each do |line|
      if (line.count("|") > 0)
        @key_id, @key_secret = line.chomp.split("|")
      else
        if key == "id"
          @key_id = value
        elsif key == "secret"
          @key_secret = value
        else
          puts "Unexpected key (#{key}) in auth file #{filename}"
        end
      end
    end
    if @verbose
      puts "AuthFile: id=#{@key_id} secret=#{@key_secret}"
    end
    if @key_id == nil && @key_secret == nil
      puts "missing both key ID and secret in auth file"
      false
    elsif @key_id == nil
      puts "missing key ID in auth file"
      false
    elsif @key_secret == nil
      puts "missing key secret in auth file"
      false
    else
      true
    end
  end
end

def getServersFromGroup(group_name, client)
  groupList = Halo::ServerGroups.all client
  groups = groupList.select do |group|
    group.name == group_name # hex numbers might be upper or lower case
  end
  if (groups.length > 0)
    groups[0].servers(client)
  else
    []
  end
end

def serverIdInList(serverList, id)
  serverList.each{ |server| return true if (server.id.downcase == id) }
  return false
end

def filterScanResults(status_list, serverList, scan_type)
  # puts "filterScanResults: server=#{server_id} type=#{scan_type}"
  status_list.each do |ss|
    if (serverList == nil) || serverIdInList(serverList,ss.server_id.downcase)
      if (scan_type == nil) || (scan_type.downcase == ss.module.downcase)
        puts ss.to_s
      end
    end
  end
end

def extractInstanceFromServer(server,cmd_line)
  if (server.hostname.include?(cmd_line.instance_name_delimiter))
    server.hostname.split(cmd_line.instance_name_delimiter)[0]
  else
    ""
  end
end

def sortByInstance(oldList,cmd_line)
  newList = []
  instanceMap = {}
  instanceList = []
  oldList.each do |server|
    instanceName = extractInstanceFromServer(server,cmd_line)
    if (instanceMap[instanceName] == nil)
      instanceMap[instanceName] = []
      instanceList << instanceName
    end
    instanceMap[instanceName] << server
  end
  maxInstanceCount = 0
  instanceList.each do |instanceName|
    if (instanceMap[instanceName] != nil) && (instanceMap[instanceName].length > maxInstanceCount)
      maxInstanceCount = instanceMap[instanceName].length
    end
  end
  1.upto(maxInstanceCount) do |index|
    instanceList.each do |instanceName|
      list = instanceMap[instanceName]
      if (list != nil) && (list.length >= index)
        newList << list[index - 1]
      end
    end
  end
  newList
end

cmd_line = CmdArgs.new()
cmd_line.parse(ARGV)

client = Halo::Client.new
client.base_url = cmd_line.base_url
client.key_id = cmd_line.key_id
client.key_secret = cmd_line.key_secret
if cmd_line.verbose
  puts "Base URL: #{client.base_url}"
end

begin
  # must call this as it forces retrieval of auth token
  token = client.token

  if (cmd_line.url)
    # check on previously issued scan command
    cmd = Halo::ServerCommands.new({ :url => cmd_line.url })
  else
    if (cmd_line.group_name == nil)
      server_list = Halo::Servers.all(client,'active')
      puts "Found #{server_list.length} servers" if cmd_line.verbose
      if (cmd_line.get_status)
        status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,cmd_line.starting,nil)
        filterScanResults(status_list,nil,cmd_line.scantype)
        # puts "Count=#{count} NextLink=#{next_link}" if cmd_line.verbose
        while (next_link != nil)
          status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,nil,next_link)
          filterScanResults(status_list,nil,cmd_line.scantype)
          # puts "Count=#{count} NextLink=#{next_link}" if cmd_line.verbose
        end
      else
        server_list.each { |s| puts "Server: #{s.hostname}  id=#{s.id}" }
      end
      exit
    end
    if (cmd_line.group_name != 'ALL')
      serverList = getServersFromGroup(cmd_line.group_name, client)
      if (serverList != nil)
        puts "Found #{serverList.length} servers in group #{cmd_line.group_name}" if cmd_line.verbose
      else
        puts "No servers in group #{cmd_line.group_name}"
      end
    else
      serverList = Halo::Servers.all(client,'active')
      puts "Found #{serverList.length} servers" if cmd_line.verbose
    end
    if (serverList.length < 1)
      puts "Group not found or group is empty"
      exit
    end
    if (cmd_line.roundrobin)
      serverList = sortByInstance(serverList,cmd_line)
    end
    if (cmd_line.get_status)
      status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,cmd_line.starting,nil)
      filterScanResults(status_list,serverList,cmd_line.scantype)
      # puts "Count=#{count} NextLink=#{next_link}" if cmd_line.verbose
      while (next_link != nil)
        status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,nil,next_link)
        filterScanResults(status_list,serverList,cmd_line.scantype)
        # puts "Count=#{count} NextLink=#{next_link}" if cmd_line.verbose
      end
      exit
    end
    cmdList = []
    serverCount = 0
    serverList.each do |server|
      puts "Starting #{cmd_line.scantype} scan on #{server.hostname}" if cmd_line.verbose
      next if cmd_line.listonly
      begin
        cmd = server.start_scan(client,cmd_line.scantype)
        if (cmd_line.delay != nil)
          sleep cmd_line.delay
        end
      rescue Halo::FailedException => api_err
        if (api_err.http_status == 422)
          puts "Failed to start #{cmd_line.scantype} scan on #{server.hostname}: #{api_err.error_msg}"
        else
          raise api_err # throw it to be caught in outer rescue clause
        end
      end
      puts "Initial scan status: #{cmd.status}"
      cmdList << cmd
      serverCount += 1
      if (cmd_line.firstx != nil) && (serverCount >= cmd_line.firstx)
        break
      end
    end
  end
  if (! cmd_line.nopoll)
    0.upto(18) do |x|
      sleep 5
      allDone = true
      cmdList.each do |cmd|
        cmd.update_status(client)
        puts "Scan status: #{cmd.status}"
        if (cmd.status.downcase == "completed")
          puts "Scan results: #{cmd.result}"
          if (cmd_line.display_issues)
            issues = server[0].issues client
            puts issues.to_s
          end
        elsif (cmd.status.downcase == "failed")
          puts "Scan failed"
        else
          allDone = false
        end
      end
      exit if allDone
    end
  end
  puts "Scan still outstanding, use the following cmd to monitor:"
  puts "launchScan.rb --url=#{cmd.url}"
rescue Halo::ConnectionException => conn_err
  puts "Connection Error: " + conn_err.error_descr
  exit
rescue Halo::AuthException => api_err
  puts "Auth Error: status=#{api_err.http_status} msg=" + api_err.error_msg
  puts "            description=" + api_err.error_description
  puts "            body=" + api_err.error_body
  exit  
rescue Halo::FailedException => api_err
  puts "API Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  puts "           description=#{api_err.error_description}"
  puts "           method=#{api_err.method} url=#{api_err.url}"
  puts "           body=" + api_err.error_body
  exit  
end
