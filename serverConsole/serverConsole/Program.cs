using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;


namespace serverConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Server Started...");

            //  Set the TcpListener on host 127.0.0.1 , port 13000.
            Int32 port = 13000;
            string localAddr = "127.0.0.1";

            // Send host address and port to Server class
            Server server = new Server(localAddr, port);

            // Start listening for client requests.
            server.startListening();

            Console.ReadLine();
        }
    }
}
