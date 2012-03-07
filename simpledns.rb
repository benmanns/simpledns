#!/usr/bin/env ruby

require 'socket'
require 'timeout'

$LOAD_PATH << File.dirname(__FILE__)

require 'dns'
require 'query'
require 'response'

DNS_NAME = ARGV.shift || '--usage'
DNS_SERVER = ARGV.shift || '8.8.8.8'

if DNS_NAME == '--usage'
  puts 'simpledns.rb --usage'
  puts 'simpledns.rb domain-name [dns-server]'
  exit
end

client = UDPSocket.new
client.connect DNS_SERVER, 53

query = Dns::Query.new
query.id = 0x1234
query.recursion_desired = true
query.questions << Dns::Question.new(DNS_NAME, :A, :IN)

client.send query.to_data, 0
response = client.recvfrom 512

data = response.first

response = Dns::Response.parse(data)

puts 'Simple DNS'
puts '= Response ='
puts "  Id: #{response.id}"
puts "  Flags: #{response.flags}"
puts "    Mode: #{response.mode}"
puts "    Opcode: #{response.opcode}"
puts "    Authoritative: #{response.authoritative?}"
puts "    Truncation: #{response.truncation?}"
puts "    Recursion Desired: #{response.recursion_desired?}"
puts "    Recursion Available: #{response.recursion_available?}"
puts "    Zero: #{response.zero}"
puts "    Response Code: #{response.response_code}"
puts '= Questions ='
response.questions.each do |question|
  puts "  Name: #{question.name}"
  puts "  Type: #{question.type}"
  puts "  Class: #{question.klass}"
  puts '===='
end
puts '= Answers ='
response.answers.each do |answer|
  puts "  Name: #{answer.name}"
  puts "  Type: #{answer.type}"
  puts "  Class: #{answer.klass}"
  puts "  Time to Live: #{answer.time_to_live}"
  if answer.type == :A
    puts "  Data: #{answer.data.unpack('CCCC').join('.')}"
  else
    puts "  Data: #{answer.data.inspect}"
  end
  puts '===='
end
