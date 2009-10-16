#!/usr/bin/env ruby

require 'readline'

files = `svn st | grep ^? | awk '{print $2}'`.split
path, url = `svn info | grep -P '^Path|^URL'`.split("\n")
puts path
puts url
puts "Looking at \n\t#{files.join("\n\t")}"
if files.size > 0
  # set ignores
  count = files.size
  n = 1
  # group files by directory
  groups = {}
  files.each do |f|
    dir, file = File.split(f)
    if groups.include? dir
      groups[dir] << file
    else
      groups[dir] = [file]
    end
  end
  quit = false
  groups.each_pair do |dir, fs|
    for file in fs
      puts "[#{n} of #{count}] #{File.directory?(File.join(dir, fs)) ? "directory" : "file"} #{File.join(dir, file)} ([i]gnore|[A]dd|[s]kip|[q]uit)"
      line = Readline::readline '> '
      choice = line.downcase.strip[0, 1]
      case choice
      when 'i'
        puts "IGNORING"
        `svn propset svn:ignore #{file} #{dir}`
      when 'a', ''
        puts "adding #{File.join(dir, file)}"
        `svn add #{File.join(dir, file)}`
      when 's'
        puts "skipping #{File.join(dir, file)}" 
      when 'q'
        quit = true
        break
      end
      n += 1
    end
    break if quit
  end
  # Add all non-ignored files.
#  `svn st | grep ^? | awk '{print $2}'`.split.each do |file|
#     puts "adding #{file}"
#     `svn add #{file}`
else
  $stdout.write "No files to ignore\n"; $stdout.flush
end


