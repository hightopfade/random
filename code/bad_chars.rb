#! /usr/bin/env ruby

def createArray

	a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f']
	b = []

	a.each do |x|
		a.each do |y|
			b << "\\x#{x}#{y}"
		end
	end

	return b

end

def chunkArray(array)

	split_array = array.each_slice(16).to_a

	return split_array

end

def printArray(array)

	cnt = 0
	array.each do |x|
		if cnt == 0
			puts "bad_chars =  \"#{x.join}\""
			cnt += 1
		else
			puts "bad_chars << \"#{x.join}\""
		end
	end

end

if ARGV.empty?
	cnt = 0
	a = chunkArray(createArray)
	puts "[+] Array Length: #{a.flatten.length} bytes"
	printArray(a)
elsif ARGV[0] == '-b'
	bad_chars = ARGV[1].split("x").reject(&:empty?)
	c = createArray
	createArray.each do |d|
		bad_chars.each do |e|
			if d.include? e
				idx = c.index("#{d}")
				c.delete_at(idx)
			end	
		end
	end
	puts "[+] Array Length: #{c.flatten.length} bytes"
	puts "[+] Bad Characters: #{ARGV[1].gsub("x", "\\x")}"
	fnl = chunkArray(c)
	printArray(fnl)
end
