# PowerInject - Inject Interactive PowerShell into an arbitrary process
*Proof Of Concept*

*WARNING* Contains some Jank that may crash processes (see `limitations` below)

# Goal:
I was reading https://itm4n.github.io/localservice-privileges, and it
made me think about the usefullness to having an interactive terminal
that could be injected into any arbitrary process.

This could help understand the attack surface of specific process, if
there was any flaw that could lead to arbitary code execution, such as
a DLL hijack, etc.


# Usage
1. Build the solution
2. Start a `ncat` listener or equivilant on `127.0.0.1:8080`
3. Run powerinjectRunner passing the PID of the process you wish to inject into
4. type `exit` when you wish to exit

# How it works
We create a remote thread to inject a C 'bootstrap' DLL into the process, and then
call a function in it. This function will load and setup the CLR runtime, and then
load *another* DLL, this one a managed C# Class DLL, and call a function in that.

The C# DLL will start a PowerShell runtime, then make a TCP connection to `127.0.0.1:8080`.
It will talk over this socket to recive and execute powershell scrippts

# Current Limitations
These would be fixed before I stop calling this a PoC

## Hardcoded port
I just hardcoded the localhost port PowerShell will communicate over to `8080`

## Hardcoded .NET Runtime version
Should be able to use `EnumerateInstalledRuntimes` and find the latest supported installed version.

## Unloading Jank
ATM unloading doesn't work, so the DLLs remain loaded in the processes, and you can't
re-load them `:-(`. This mean you gotta kill to process or use Process Hacker to unload
the modules. Doing this can kill the processes, so rip.

## only tested x64
Haven't checked x86 yet
