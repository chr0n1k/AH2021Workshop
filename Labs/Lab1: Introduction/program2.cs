using System;
using System.Runtime.InteropServices;

namespace PopMessage
{
	public class Program
	{
		// Use DllImport to import the Win32 MessageBox function.
		[DllImport("user32.dll", CharSet = CharSet.Unicode)]
		public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);
		
		static void Main(string[] args)
		{
			// Call the MessageBox function using platform invoke.
			MessageBox(new IntPtr(0), "Find the DLL import!!", "Just Popped", 0);
		}
	}
}
