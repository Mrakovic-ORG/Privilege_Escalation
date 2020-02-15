using System;
using System.Diagnostics;

namespace Privilege_Escalation
{
    internal static class Program
    {
        private static void Main()
        {
            Console.Clear();
            Console.Title = "Privilege Escalation";

            Console.WriteLine("Using: " + UAC.GetWindowsName());

            //This part will return if current process is elevated
            var isUAC = UAC.IsRunningAsLocalAdmin() ? "Yes" : "No";
            Console.WriteLine($"UAC: {isUAC}");

            //If you run into trouble please use failsafe in compatibility mode
            Console.WriteLine("Numpad 1: Start UAC Bypass\nNumpad 2: RemoteShell\nNumpad 3: Compatibility mode");
            switch (Console.ReadKey().Key)
            {
                case ConsoleKey.NumPad1:
                    UAC.Start();
                    break;
                case ConsoleKey.NumPad2:
                    RemoteShell();
                    break;
                case ConsoleKey.NumPad3:
                    UAC.Compatibility();
                    break;
            }
        }

        private static void RemoteShell()
        {
            Console.Write("\b");
            Console.WriteLine("Shell: ");
            var input = Console.ReadLine();
            if (input != null) Process.Start(input);

            Main();
        }
    }
}
