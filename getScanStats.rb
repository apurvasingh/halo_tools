#!/usr/bin/env ruby

require 'rubygems'
require 'halo-api-lib'
require 'fileutils'
require 'time'

$scanTimes = {}
$scanTimes["svm"] = []
$scanTimes["sca"] = []
$scanTimes["fim"] = []
$scanTimes["sam"] = []

def addScanTime(type,created_at,completed_at)
  if ((created_at == nil) || (completed_at == nil))
    return
  end
  created_dt = Time.iso8601(created_at)
  completed_dt = Time.iso8601(completed_at)
  scan_time = completed_dt - created_dt
  list = $scanTimes[type]
  if (list == nil)
    list = []
    $scanTimes[type] = list
  end
  list << scan_time
end

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
  attr_accessor :base_url, :key_id, :key_secret, :verbose, :page_size, :details, :percentiles
  attr_accessor :group_name, :display_issues, :get_status, :starting, :ending, :threads, :debug

  def initialize()
    @base_url = "https://portal.cloudpassage.com/"
    @key_id = "05266dad"
    @key_secret = "03f7ce883627f654cc877f67c9d61393"
    @url = nil
    @group_name = nil
    @verbose = false
    @display_issues = false
    @get_status = false
    @starting = nil
    @ending = nil
    @page_size = 100
    @details = :None
    @percentiles = false
    @threads = 1
    @debug = false
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
      elsif (arg.start_with?("--debug"))
        @debug = true
        @page_size = 20
      elsif (arg.start_with?("--threads="))
        argarg, tmptc = arg.split("=")
        begin
          @threads = Integer(tmptc)
          if (@threads < 1) || (@threads > 100)
            puts "Illegal thread number: #{@threads}"
            puts "--thread=<num> requires an integer between 1 and 100"
            ok = false
          end
        rescue
          puts "Invalid thread number: #{tmptc}"
          puts "--thread=<num> requires an integer between 1 and 100"
          ok = false
        end
      elsif (arg == "--localca")
        ENV['SSL_CERT_FILE'] = File.expand_path(File.dirname(__FILE__)) + "/certs/cacert.pem"
      elsif (arg == "--details")
        @details = :Console
      elsif (arg == "--detailsfiles")
        @details = :Files
      elsif (arg == "--percentile") || (arg == "--percentiles")
        @percentiles = true
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
    puts "    --localca\t\t\tUse local CA file (needed on Windows)"
    # puts "    --issues\t\t\tDisplay issues found by scan"
    puts "    --details\t\t\tDisplay details about each scan's results"
    puts "    --detailsfiles\t\tWrite details about each scan's results to a set of files"
    puts "    --percentile\t\tCalculate percentiles of scan times"
    puts "    --threads=<num>\t\tSet number of threads to use downloading scan results"
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
    if @debug
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

def openFileInDir(path)
  dirname = File.dirname(path)
  unless File.directory?(dirname)
    FileUtils.mkdir_p(dirname)
  end
  File.open(path,"w+")
end

def serverIdInList(serverList, id)
  serverList.each{ |server| return true if (server.id.downcase == id) }
  return false
end

def filterScanResults(status_list, serverList, scan_type, statisticsMap, cmd_line, client)
  scanResultsList = []
  status_list.each do |ss|
    if (serverList == nil) || serverIdInList(serverList,ss.server_id.downcase)
      if (scan_type == nil) || (scan_type.downcase == ss.module.downcase)
        puts "Processing scan results #{ss.id}" if cmd_line.debug
        statBucketName = ss.module.downcase
        statBucket = statisticsMap[statBucketName]
        if (statBucket == nil)
          statBucket = ScanStats.new statBucketName
          statisticsMap[statBucketName] = statBucket
        end
        if (ss.status == "completed_with_errors") || (ss.status == "completed_clean")
          statBucket.increment(true)
        elsif (ss.status == "failed")
          statBucket.increment(false)
        end
        addScanTime(statBucketName,ss.created_at,ss.completed_at)
        ss.get_details(client) if (cmd_line.details != :None)
        scanResultsList << ss
      end
    end
  end
end

def displayScanResults(scanList,verbose,details)
  scanList.each do |ss|
    puts ss.to_s if verbose
    if (ss.details != nil)
      if (details == :Console)
        puts JSON.pretty_generate ss.details
      elsif (details == :Files)
        filename = "details/#{ss.server_id.downcase}/#{ss.module.downcase}_#{ss.id}_details.txt"
        f = openFileInDir(filename)
        f.write(JSON.pretty_generate ss.details)
        f.close()
      end
    end
  end
end

def singleThreadStats(client,cmd_line,serverList)
  statisticsMap = {}
  status_list, next_link, count = Halo::ScanStatus.all(client,cmd_line.page_size,nil,cmd_line.starting,cmd_line.ending,nil)
  resultsList = filterScanResults(status_list,serverList,nil,statisticsMap,cmd_line,client)
  displayScanResults(resultsList,cmd_line.verbose,cmd_line.details)
  while (next_link != nil)
    begin
      status_list, next_link, count = Halo::ScanStatus.all(client,nil,nil,nil,nil,next_link)
      # sleep(500) if cmd_line.debug
    rescue Halo::AuthException => api_err
      client.token # re-authorize
      puts "Re-authorizing..." if cmd_line.debug
      redo
    end
    resultsList = filterScanResults(status_list,serverList,nil,statisticsMap,cmd_line,client)
    displayScanResults(resultsList,cmd_line.verbose,cmd_line.details)
  end
  statisticsMap.each do |stype,bucket|
    puts "Scan: type=#{bucket.type_name} passed=#{bucket.pass_count} failed=#{bucket.fail_count}"
  end
end

class FetchResultsThread
  def initialize(client,cmd_line,serverList,start,increment,threadMap,outputMap,statsMap)
    @client = client
    @cmd_line = cmd_line
    @serverList = serverList
    @start = start
    @increment = increment
    @threadMap = threadMap
    @outputMap = outputMap
    @threadMap["#{@start}"] = self
    @statisticsMap = {}
    statsMap["#{start}"] = @statisticsMap
  end

  def start
    Thread.new { self.run }
  end

  def run
    begin
      pageNum = @start
      puts "Starting thread number #{pageNum}" if @cmd_line.debug
      retry_count = 0
      begin
        begin
          status_list, next_link, count = Halo::ScanStatus.all(@client,@cmd_line.page_size,pageNum,
                                                               @cmd_line.starting,@cmd_line.ending,nil)
        rescue Halo::AuthException => api_err
          puts "Re-authorizing..." if @cmd_line.debug
          @client.token # re-authorize
          redo
        rescue Halo::FailedException => bad_err
          if (retry_count > 3)
            puts "Thread #{@start} failed, exiting: #{ex.message}"
            exit 1
          else
            retry_count += 1
            puts "Thread #{@start} failed, retrying: #{ex.message}"
            redo
          end
        end
        puts "Received #{status_list.size} scan results (thread #{@start})" if @cmd_line.debug
        resultsList = filterScanResults(status_list,@serverList,nil,@statisticsMap,@cmd_line,@client) if status_list != nil
        @outputMap["#{pageNum}"] = resultsList
        puts "Storing output for page #{pageNum}" if @cmd_line.debug
        pageNum += @increment
      end until (status_list == nil) or (status_list.size == 0)
    rescue Exception => ex
      puts "Thread #{@start} failed, exiting: #{ex.message}"
    end
    @threadMap.delete("#{@start}")
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
  if (cmd_line.threads < 2)
    singleThreadStats(client,cmd_line,serverList)
  else
    threadMap = {}
    outputMap = {}
    statsMap  = {}
    puts "Running #{cmd_line.threads} threads" if cmd_line.debug
    1.upto(cmd_line.threads) do |start|
      t = FetchResultsThread.new(client,cmd_line,serverList,start,cmd_line.threads,threadMap,outputMap,statsMap)
      t.start
    end
    # now run consuming thread
    pageNum = 1
    key = "#{pageNum}"
    while (threadMap.size > 0) || (outputMap.size > 0)
      rez = outputMap[key]
      if (rez != nil)
        displayScanResults(rez,cmd_line.verbose,cmd_line.details)
        outputMap.delete(key)
        pageNum += 1
        key = "#{pageNum}"
        puts "Completed page #{pageNum} output" if cmd_line.debug
      else
        sleep(0.1)
      end
    end
    sumMap = {}
    1.upto(cmd_line.threads) do |start|
      threadStats = statsMap["#{start}"]
      threadStats.each do |stype,bucket|
        if (sumMap[stype] == nil)
          sumMap[stype] = ScanStats.new stype
        end
        sumMap[stype].pass_count += bucket.pass_count
        sumMap[stype].fail_count += bucket.fail_count
      end
    end
    sumMap.each do |stype,bucket|
      puts "Scan: type=#{bucket.type_name} passed=#{bucket.pass_count} failed=#{bucket.fail_count}"
    end
  end
  if (cmd_line.percentiles)
    puts "Scan Type\t50%\t75%\t85%\t90%\t95%"
    [ "sca", "svm", "fim", "sam" ].each do |type|
      list = $scanTimes[type]
      list.sort!
      str = "#{type}\t"
      if (list.length > 10)
        [ 50, 75, 85, 90, 95 ].each do |percent|
          index = (list.length * percent) / 100
          str += "\t#{list[index]}"
        end
      else
        str = "No enough scan results to compute percentiles"
      end
      puts str
    end
  end
rescue Halo::ConnectionException => conn_err
  puts "Connection Error: #{conn_err.error_descr}"
  exit
rescue Halo::AuthException => api_err
  puts "Auth Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  puts "            description=#{api_err.error_description}"
  puts "            body=#{api_err.error_body}"
  exit  
rescue Halo::FailedException => api_err
  puts "API Error: status=#{api_err.http_status} msg=#{api_err.error_msg}"
  puts "           description=#{api_err.error_description}"
  puts "           method=#{api_err.method} url=#{api_err.url}"
  puts "           body=#{api_err.error_body}"
  exit  
end
