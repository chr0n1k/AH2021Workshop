# Malware development workshop.

Welcome to the Malware Development workshop for AfricaHackon 2021. In this interactive workshop, we will take a look at the C# language and how to write malware focused on droppers/loaders that will run shellcode on Windows 10 targets that give a meterpreter session back.

The flow of this workshop is building out the code like how virus research looks at Gain of Function. We start of with a simple shellcode runner and build out from there.

> In order to be able to follow the workshop properly, it is highly recommended to go through Lab 0 before the start of the workshop, as this is a setup lab to get you up and ready. You can get it here: [Lab0](https://github.com/chr0n1k/AH2021Workshop/blob/master/LabGuide/AH2021%20Workshop%20-%20Lab0.pdf)

* Skill Level: Intermediate

* Prerequisites: Basic to intermediate programming/scripting skills. Prior experience with C# helps but not required.

* Materials: Laptop with virtualization software. A Windows 10 virtual machine and a Kali Linux Virtual Machine.

## Author: 
Amarjit Labhuram - [@Amarjit_Labu](https://twitter.com/Amarjit_Labu)

## Labs:

Lab1: Introduction
------
The goal of this lab is to introduce basic C# coding and use of .NETs Platform Invoke (p/invoke) to access the Win32 API. We will also look at how to use System.Reflection.Assembly in powershell to run one of the programs without having to touch disk.

Lab2: Simple shellcode runner
------
The goal of this lab is to be able to create a simple shellcode runner that will execute shellcode generated from msfvenom in csharp format on a Windows 10 device. We will look at the various Win32 API calls needed to achieve this and leverage p/invoke to achieve this.

Lab3: AV signature and heuristic evasion
------
The goal of this lab is to enhance the shellcode runner to be able to use some behavioural tactics to bypass sandbox and AV checks.

Lab4: Simple process injection
------
The goal of this lab is to understand process injection and enhance our shellcode runner to be able to spawn a notepad process and inject into it.

Lab5: RemoteThreadSuspended process injection
------
The goal of this lab is to enhance the Simple process injection code to create memory regions with lower malicious footprint.

Lab6: QueueUserAPC process injection
------
The goal of this lab is to leverage the Queue Asynchronus Procedure Call to do process injection.

Lab7: Let's bypass userland hooks [EDR]
------
The goal of this lab is to understand what are system calls and the hooking that EDRs do on to ntdll.dll to detect use of malicious syscalls and block them. We will rewrite the QueueUserAPC process injection code to dynamically invoke the syscalls using d/invoke.

## Goals:
* AntiVirus bypass
* Defense evasion by Process Injection
* Defense evasion of EDR's that use Userland hooks.

## Acknowledgments

All the code snippets in this workshop started from a Github repository/gist, a Stack Overflow code snippet or a Google search. Special mention goes out to:

* Mauricio Velazco - [Github](https://github.com/mvelazc0) | [Twitter](https://twitter.com/mvelazco)
* Jean Francois Maes - [Github](https://github.com/jfmaes) | [Twitter](https://twitter.com/Jean_Maes_1994)
* John Tear - [Github](https://github.com/plackyhacker)
* Cas Van Cooten - [Github](https://github.com/chvancooten) | [Twitter](https://twitter.com/chvancooten)
* Chirag Savla - [Github](https://github.com/3xpl01tc0d3r) | [Twitter](https://twitter.com/chiragsavla94)
