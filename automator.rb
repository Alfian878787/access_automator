#!/usr/bin/env ruby

require 'json'
require 'aws-sdk-ec2'
require 'net/ssh'
require 'net/scp'
require 'net/ping'
require 'thor'

# AccessAutomator
#
# Thor Menu baked in
#
class AccessAutomator < Thor
  def initialize(*args)
    super
    puts '-------------- Access Automator ----------------'
    @adminkey = read_in_admin_key
    @ssh_options = {}
    @ssh_options[:auth_methods] = ['publickey']
    @ssh_options[:keys] = [@adminkey.to_s] if @adminkey
    @ssh_options[:timeout] = 5
  end

  desc 'grant', 'Grant a user access to a group of servers'
  long_desc <<-LONGDESC
    `grant` will grant a USER access to a GROUP of servers

    You must specify a user as the first parameter, and a group
    as the second parameter:

    \x5> $ grant tony app-servers
  LONGDESC
  def grant(user, group)
    puts "Granting access to #{user.capitalize} on #{group}'s\n\n"
    servers = get_server_group(group)
    generate_user_key(user)
    servers.each do |server|
      verify_connectivity(server)
      if verify_user(user, server)
        puts "\tUser is already present on the system. Nothing to see here."
      else
        add_access(user, server)
      end
    end
    show_user_key
  end

  desc 'revoke', 'Revoke user access to a group of servers'
  long_desc <<-LONGDESC
    `revoke` will revoke a USER access to a GROUP of servers

    You must specify a user as the first parameter, and a group
    as the second parameter:
  
    \x5> $ revoke tony app-servers
  LONGDESC
  def revoke(user, group)
    puts "Revoking access to #{user.capitalize} on #{group}'s\n\n"
    servers = get_server_group(group)
    servers.each do |server|
      verify_connectivity(server)
      if verify_user(user, server)
        revoke_access(user, server)
      else
        puts "\tUser doesn't exist. Nothing to see here."
      end
    end
  end

  no_tasks do
    # Returns an array of server IP's
    def get_server_group(group)
      array = []
      ec2 = Aws::EC2::Client.new
      results = ec2.describe_instances(
        filters: [{ name: 'tag:Type', values: [group.to_s] }]
      )
      get_server_instances(results).each do |instance|
        array.push(instance.private_ip_address)
      end
      verify_instance_array(array, group)
    end

    def verify_instance_array(array, group)
      if array.empty? || array.nil?
        puts "ERROR: No instances found with #{group} tag."
        exit 1
      end
      array
    end

    # Returns an array of instances
    def get_server_instances(results)
      results.each do |result|
        reservations = result.reservations
        reservations.each do |res|
          return res.instances
        end
      end
    end

    # Make sure that we are able to ping a server
    # Doesn't work on Docker for MAC
    def check_ping(server)
      icmp = Net::Ping::ICMP.new(server)
      puts icmp.inspect
      pingfails = 0
      repeat = 5
      puts 'starting to ping'
      (1..repeat).each do
        if icmp.ping
          puts 'host replied'
        else
          pingfails += 1
          puts 'timeout'
        end
      end
      puts "#{pingfails} packets were droped"
    end

    # Make sure that we are able to connect to a server
    def verify_connectivity(server)
      checked = sshTo(server, 'root', 'ls')
      if checked == 'timeout'
        puts "ERROR: Unable to connect to the server. Check your connection."
        exit 1
      elsif checked == 'authentication'
        puts "ERROR: You're private key is invalid. Please check your access."
        exit 1
      end
    end

    # Check if the user exists
    def verify_user(user, server)
      puts "Verifying #{user} on #{server}"
      cmd = "grep -q #{user} /etc/passwd"
      checked = sshTo(server, 'root', cmd)
      if checked[:exit_code] == 0
        true
      else
        false
      end
    end

    def ssh_exec!(ssh, command)
      stdout_data = ""
      stderr_data = ""
      exit_code = nil
      exit_signal = nil
      ssh.open_channel do |channel|
        channel.exec(command) do |ch, success|
          unless success
            abort "FAILED: couldn't execute command (ssh.channel.exec)"
          end
          channel.on_data do |ch,data|
            stdout_data+=data
          end

          channel.on_extended_data do |ch,type,data|
            stderr_data+=data
          end

          channel.on_request("exit-status") do |ch,data|
            exit_code = data.read_long
          end

          channel.on_request("exit-signal") do |ch, data|
            exit_signal = data.read_long
          end
        end
      end
      ssh.loop
      { :stdout_data => stdout_data, :stderr_data => stderr_data, :exit_code => exit_code, :exit_signal => exit_signal}
    end

    def add_access(user, server)
      puts "\tAdding #{user} to #{server}"
      cmd1 = "useradd #{user}"
      cmd2 = "mkdir -p /home/#{user}/.ssh"
      sshTo(server, 'root', cmd1)
      sshTo(server, 'root', cmd2)
      copy_user_key(user, server)
    end

    def revoke_access(user, server)
      puts "\tRevoking #{user} from #{server}"
      cmd1 = "userdel #{user}"
      cmd2 = "rm -rf /home/#{user}"
      sshTo(server, 'root', cmd1)
      sshTo(server, 'root', cmd2)
    end

    def generate_user_key(user)
      File.delete("/root/.ssh/#{user}")
      #puts "Generating a Key Pair for #{user}"
      system("ssh-keygen -t rsa -f /root/.ssh/#{user} -N '' > /dev/null 2>&1")
      @userkey = File.read("/root/.ssh/#{user}")
    end

    def copy_user_key(user, server)
      auth_key = "/home/#{user}/.ssh/authorized_keys"
      scpTo(server, 'root', "/root/.ssh/#{user}.pub", auth_key)
      cmd1 = "chown -R #{user}:#{user} /home/#{user}/.ssh"
      cmd2 = "chmod 700 /home/#{user}/.ssh"
      cmd3 = "chmod 644 #{auth_key}"
      sshTo(server, 'root', cmd1)
      sshTo(server, 'root', cmd2)
      sshTo(server, 'root', cmd3)
    end

    def show_user_key
      puts @userkey
    end

    def sshTo(server, user, cmd)
      begin
        Net::SSH.start(server, user, @ssh_options) do |ssh|
          ssh_exec!(ssh, cmd)
        end
      rescue Net::SSH::ConnectionTimeout
        'timeout'
      rescue Net::SSH::AuthenticationFailed
        'authentication'
      end
    end

    def scpTo(server, user, local, remote)
      begin
        Net::SSH.start(server, user, @ssh_options) do |ssh|
          ssh.scp.upload!(local, remote)
        end
      rescue Net::SSH::ConnectionTimeout
        'timeout'
      rescue Net::SSH::AuthenticationFailed
        'authentication'
      end
    end

    def read_in_admin_key
      return nil unless File.exist?('config.json')
      config = File.read('config.json')
      hash = JSON.parse(config)
      key = hash['private_key']
      "/root/.ssh/#{key}"
    end
  end
end

AccessAutomator.start(ARGV)
