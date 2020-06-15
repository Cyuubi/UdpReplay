using System;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Text;
using System.IO;

namespace UdpReplay
{
    class Program
    {
        private class PacketInfo
        {
            public byte[] Data;
            public bool IsServer;

            public PacketInfo(byte[] data, bool isServer)
            {
                Data = data;
                IsServer = isServer;
            }
        }

        private static string _clientHardwareAddress = string.Empty;

        private static int _packetIndex = 0;

        private static Dictionary<int, PacketInfo> _packets = new Dictionary<int, PacketInfo>();

        static void Main(string[] args)
        {
            if (args == null || args.Length <= 2)
            {
                Console.WriteLine($"{Process.GetCurrentProcess().ProcessName}.exe <Capture File> <Client Hardware Address> <Server Port>");
                return;
            }

            _clientHardwareAddress = args[1].Replace(":", string.Empty).ToUpper();

            ICaptureDevice device;

            try
            {
                device = new CaptureFileReaderDevice(args[0]);
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occured while opening capture file: {e.ToString()}");
                return;
            }

            device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);

            device.Capture();
            device.Close();

            Console.WriteLine("Reading capture file finished, press any key to start server!");
            Console.ReadKey();

            _packetIndex = 0;

            byte[] buffer = new byte[32768];

            IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, Convert.ToInt32(args[2]));
            UdpClient udpClient = new UdpClient(endPoint);

            IPEndPoint sender = new IPEndPoint(IPAddress.Any, 0);

            buffer = udpClient.Receive(ref sender);

            _packetIndex++;

            PushPackets(udpClient, sender);

            while (true)
            {
                buffer = udpClient.Receive(ref sender);

                _packetIndex++;

                PushPackets(udpClient, sender);
            }
        }

        private static void PushPackets(UdpClient udpClient, IPEndPoint sender)
        {
            for (int index = _packetIndex; index < _packets.Count - 1; index++)
            {
                PacketInfo packetInfo = _packets[index];

                if (packetInfo.IsServer)
                {
                    udpClient.Send(packetInfo.Data, packetInfo.Data.Length, sender);

                    _packetIndex = index;
                }

                // If the next packet is from the client, stop the for loop.
                // Otherwise, continue the for loop so that we can send the next server packet.
                if (!_packets[index + 1].IsServer) break;
            }
        }

        private static void OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (e.Packet.LinkLayerType == LinkLayers.Ethernet)
            {
                Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                EthernetPacket ethernetPacket = (EthernetPacket)packet;

                if (ethernetPacket.PayloadPacket.PayloadPacket.HasPayloadData)
                {
                    using (MemoryStream stream = new MemoryStream(e.Packet.Data))
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        stream.Seek(0x26, SeekOrigin.Begin);

                        byte[] _length = reader.ReadBytes(2);
                        Array.Reverse(_length);

                        ushort length = BitConverter.ToUInt16(_length, 0);
                        if (length != ethernetPacket.PayloadPacket.PayloadPacket.PayloadData.Length + 8)
                        {
                            Console.WriteLine($"Packet {_packetIndex} has failed length check, this packet will be ignored.");
                            Console.WriteLine($"    Expected Length = {length}, Actual Length = {ethernetPacket.PayloadPacket.PayloadPacket.PayloadData.Length}");

                            return;
                        }
                    }

                    _packets.Add(_packetIndex, new PacketInfo(RemoveTrailingZeros(ethernetPacket.PayloadPacket.PayloadPacket.PayloadData), ethernetPacket.SourceHardwareAddress.ToString() != _clientHardwareAddress));

                    _packetIndex++;
                }
            }
        }

        private static byte[] RemoveTrailingZeros(byte[] value)
        {
            int index = value.Length - 1;

            while (value[index] == 0) --index;

            byte[] result = new byte[index + 1];
            Array.Copy(value, result, index + 1);

            return result;
        }
    }
}
