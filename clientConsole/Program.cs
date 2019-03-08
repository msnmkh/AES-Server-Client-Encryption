using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace clientConsole
{
    class Program 
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Client Started...");

            // Set Ip and port of server.
            string localIP = "127.0.0.1";
            Int32 port = 13000;

            // Send host address and port to Client class
            Client client = new Client(localIP, port);

            // Connect to server and exchange public key
            client.connectToServer();

            // Send message to server and get response
            string message = "hello";
            client.sendMessage(message);

            Console.ReadLine();
        }
    }
}
