using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace serverConsole
{
    class Server
    {
        TcpClient client;
        TcpListener tcpListener;
        NetworkStream stream;
        Int32 port;
        IPAddress iPAddress;
        string ij;
        string k;
        Byte[] iv;
        Byte[] key;
        int i;

        // Buffer for reading data
        Byte[] bytes;

        public Server(string ip , Int32 prt) {
            iPAddress = IPAddress.Parse(ip);
            port = prt;

            ij = "qo1lc3sjd8zpt9cx";
            k = "ow7dxys8glfor9tnc2ansdfo1etkfjvc";
            iv = ASCIIEncoding.ASCII.GetBytes(ij);
            key = ASCIIEncoding.ASCII.GetBytes(k);
        }

        public void startListening()
        {
            try
            {
                // TcpListener server = new TcpListener(port);
                tcpListener = new TcpListener(iPAddress, port);

                // Start listening for client requests.
                tcpListener.Start();

                Console.Write("Waiting for a connection... ");

                // Perform a blocking call to accept requests.
                // You could also user server.AcceptSocket() here.
                client = tcpListener.AcceptTcpClient();
                Console.WriteLine("Connected!");

                // Get a stream object for reading and writing
                stream = client.GetStream();

                bytes = new Byte[256];

                // Loop to receive all the data sent by the client.
                while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    // deleteZero(byte[] variable) for delete null elements.
                    var newbytes = deleteZeroBytes(bytes);

                    // Decrypt message
                    byte[] decryptMSG = Encryption.Decrypt(newbytes, key, Encryption.Mode.CBC, iv, Encryption.Padding.PKCS7);
                    string decrypteMessageString = System.Text.Encoding.ASCII.GetString(decryptMSG, 0, decryptMSG.Length);

                    Console.WriteLine("Received: {0}", decrypteMessageString);

                    // Process the data sent by the client.
                    string responseData = decrypteMessageString + decrypteMessageString;

                    // Get bytes of response
                    byte[] messageBytes = System.Text.Encoding.ASCII.GetBytes(responseData);

                    // Encrypt response response
                    byte[] encryptMessage = Encryption.Encrypt(messageBytes, key, Encryption.Mode.CBC, iv, Encryption.Padding.PKCS7);

                    // Send response to client 
                    stream.Write(encryptMessage, 0, encryptMessage.Length);

                    Console.WriteLine("Sent: {0}", responseData);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: " + e.Message);
            }
        }

        // deleteZero(byte[] variable) for delete null elements.
        public byte[] deleteZeroBytes(byte[] packet)
        {
            var i = packet.Length - 1;
            while (packet[i] == 0)
            {
                --i;
            }
            var temp = new byte[i + 1];
            Array.Copy(packet, temp, i + 1);

            return temp;
        }
    }
}
