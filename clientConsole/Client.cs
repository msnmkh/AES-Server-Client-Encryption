using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;


namespace clientConsole
{
    class Client
    {
        TcpClient client;
        private string localIP;
        private Int32 port;
        NetworkStream stream;
        string i;
        string k;
        Byte[] iv;
        Byte[] key;

        // Buffer for reading data
        Byte[] bytes = new Byte[256];

        public Client(string localIP, Int32 port)
        {
            this.localIP = localIP;
            this.port = port;

            i = "qo1lc3sjd8zpt9cx";
            k = "ow7dxys8glfor9tnc2ansdfo1etkfjvc";
            iv = System.Text.Encoding.ASCII.GetBytes(i);
            key = System.Text.Encoding.ASCII.GetBytes(k);
        }


        public void connectToServer()
        {
            try
            {
                // Create a TcpClient.
                client = new TcpClient();

                // Connect to server.
                client.Connect(localIP, port);

                // Get a client stream for reading and writing.
                //  Stream stream = client.GetStream();
                stream = client.GetStream();

            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
        }

        public void sendMessage(string msg)
        {
           if (client.Connected)
           {
               try
               {
                   // Get bytes of message
                   byte[] messageBytes = System.Text.Encoding.ASCII.GetBytes(msg);
          
                   // Encrypt Message
                   byte[] encryptMessage = Encryption.Encrypt(messageBytes, key, Encryption.Mode.CBC, iv, Encryption.Padding.PKCS7);

                   // Send the message to the connected TcpServer. 
                   //stream.Write()
                   stream.Write(encryptMessage, 0, encryptMessage.Length);

                    Console.WriteLine("Sent: {0}", msg);
          
                   // Read the first batch of the TcpServer response bytes.
                   Int32 i = stream.Read(bytes, 0, bytes.Length);

                    // deleteZero(byte[] variable) for delete null elements.
                    var newbytes = deleteZeroBytes(bytes);

                    // Decrypt message
                    byte[] decryptMSG = Encryption.Decrypt(newbytes, key, Encryption.Mode.CBC, iv, Encryption.Padding.PKCS7);
                    string decrypteMessageString = System.Text.Encoding.ASCII.GetString(decryptMSG, 0, decryptMSG.Length);

                    Console.WriteLine("Received: {0}", decrypteMessageString);
               }
               catch (ArgumentNullException e)
               {
                   Console.WriteLine("ArgumentNullException: {0}", e);
               }
               catch (SocketException e)
               {
                   Console.WriteLine("SocketException: {0}", e);
               }
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
