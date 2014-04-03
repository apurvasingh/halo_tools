#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'

class ScanStats
  attr_accessor :type_name, :pass_count, :fail_count

  def initialize(type)
    @pass_count = 0
    @fail_count = 0
    @type_name = type
  end

  def increment(passed)
    if passed
      @pass_count += 1
    else
      @fail_count += 1
    end
  end
end

class CmdArgs
  attr_accessor :base_url, :key_id, :key_secret, :verbose, :page_size
  attr_accessor :group_name, :display_issues, :get_status, :starting, :ending

  def initialize()
    @base_url = "https://portal.cloudpassage.com/"
    @key_id = "your_key"
    @key_secret = "your_secret"
    @url = nil
    @group_name = nil
    @verbose = false
    @display_issues = false
    @get_status = false
    @starting = nil
    @ending = nil
    @page_size = 100
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
      elsif (arg.start_with?("--starting="))
        argarg, @starting = arg.split("=")
      elsif (arg.start_with?("--ending="))
        argarg, @ending = arg.split("=")
      elsif (arg.start_with?("--base="))
        argarg, @base_url = arg.split("=")
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
    puts "    --servergroup=<groupname>\tSpecify name of server group to list scans"
    puts "    --starting=<when>\t\tOnly get status for scans after when (ISO-8601 format)"
    puts "    --ending=<when>\t\tOnly get status for scans before when (ISO-8601 format)"
    puts "    --base=<url>\t\tOverride base URL (normally #{@base_url})"
    # puts "    --issues\t\t\tDisplay issues found by scan"
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
    groups[0].servers client
  else
    []
  end
end

def serverIdInList(serverList, id)
  serverList.each{ |server| return true if (server.id.downcase == id) }
  return false
end

def filterScanResults(status_list, serverList, scan_type, statisticsMap, verbose)
  # puts "filterScanResults: server=#{server_id} type=#{scan_type}"
  status_list.each do |ss|
    if (serverList == nil) || serverIdInList(serverList,ss.server_id.downcase)
      if (scan_type == nil) || (scan_type.downcase == ss.module.downcase)
        puts ss.to_s if verbose
        statBucketName = ss.module.downcase
        statBucket = statisticsMap[statBucketName]
        if (statBucket == nil)
          statBucket = ScanStats.new statBucketName
          statisticsMap[statBucketName] = statBucket
        end
        if ss.status == "completed_clean"
          statBucket.increment(true)
        elsif (ss.status == "completed_with_errors") || (ss.status == "failed")
          statBucket.increment(false)
        end
      end
    end
  end
end

cmd_line = CmdArgs.new()
cmd_line.parse(ARGV)

client = Halo::Client.new
client.base_url = cmd_line.base_url
client.key_id = cmd_line.key_id
client.key_secret = cmd_line.key_secret

begin
  # must call this as it forces retrieval of auth token
  token = client.token

  if (cmd_line.group_name == nil)
    serverList = nil
  else
    serverList = getServersFromGroup(cmd_line.group_name, client)
  end
  statisticsMap = {}
  status_list, next_link, count = Halo::ScanStatus.all(client,cmd_line.page_size,nil,cmd_line.starting,cmd_line.ending,nil)
  filterScanResults(status_list,serverList,nil,statisticsMap,cmd_line.verbose)
  while (next_link != nil)
    status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,nil,nil,next_link)
    filterScanResults(status_list,serverList,nil,statisticsMap,cmd_line.verbose)
  end
  statisticsMap.each do |stype,bucket|
    puts "Scan: type=#{bucket.type_name} passed=#{bucket.pass_count} failed=#{bucket.fail_count}"
  end
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
