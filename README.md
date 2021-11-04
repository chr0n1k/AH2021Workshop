# Malware development workshop.

Welcome to the Malware Development workshop for AfricaHackon 2021. In this interactive workshop, we will take a look at the C# language and how to write malware focused on droppers/loaders that will run shellcode on Windows 10 targets that give a meterpreter session back.

The flow of this workshop is building out the code like how virus research looks at Gain of Function. We start of with a simple shellcode runner and build out from there.

> In order to be able to follow the workshop properly, it is highly recommended to go through Lab 0 before the start of the workshop, as this is a setup lab to get you up and ready. You can get it here: [Lab0](https://github.com/chr0n1k/AH2021Workshop/blob/master/LabGuide/AH2021%20Workshop%20-%20Lab0.pdf)

Skill Level: Intermediate

Prerequisites: Basic to intermediate programming/scripting skills. Prior experience with C# helps but not required.

Materials: Laptop with virtualization software. A Windows 10 virtual machine and a Kali Linux Virtual Machine.

## Author: 
Amarjit Labhuram - [@Amarjit_Labu](https://twitter.com/Amarjit_Labu)

## Labs:

Lab1: Introduction
The goal of this lab is to introduce basic C# coding and use of .NETs Platform Invoke to access the Win32 API. We will also look at how to use System.Reflection.Assembly in powershell to run one of the programs without having to touch disk.

Lab2: Simple shellcode runner

Lab3: AV signature and heuristic evasion

Lab4: Simple process injection

Lab5: RemoteThreadSuspended process injection

Lab6: QueueUserAPC process injection

Lab7: Let's bypass userland hooks [EDR]
