﻿using System;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
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
            public bool IsValid;
        }

        private static Dictionary<int, PacketInfo> _packets = new Dictionary<int, PacketInfo>();

        private static string _clientMacAddress = string.Empty;

        private static int _packetIndex = 0;

        static void Main(string[] args)
        {
            if (args == null || args.Length <= 2)
            {
                Console.WriteLine($"{Process.GetCurrentProcess().ProcessName}.exe <Capture> <Client MAC Address> <Port>");
                return;
            }

            _clientMacAddress = args[1].Replace(":", string.Empty).ToUpper();

            ICaptureDevice device;

            try
            {
                device = new CaptureFileReaderDevice(args[0]);
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occured while opening capture: {e}");
                return;
            }

            device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);

            device.Capture();
            device.Close();

            _packetIndex = 0;

            Console.WriteLine("Reading capture finished, press any key to start server!");
            Console.ReadKey();

            var buffer = new byte[0];
            var server = new UdpClient(new IPEndPoint(IPAddress.Any, Convert.ToInt32(args[2])));
            var sender = new IPEndPoint(IPAddress.Any, 0);

            Console.WriteLine($"Server has started on port {args[2]}.");

            while (true)
            {
                buffer = server.Receive(ref sender);

                PushPackets(server, sender);
            }
        }

        private static string EnumerableByteToString(IEnumerable<byte> enumerable)
        {
            var builder = new StringBuilder("byte[] { ");

            foreach (var b in enumerable)
                builder.Append($"0x{b:X2}, ");

            builder.Append("}");

            return builder.ToString();
        }

        private static void PushPackets(UdpClient server, IPEndPoint sender)
        {
            _packetIndex++;

            for (var index = _packetIndex; index < _packets.Count - 1; index++)
            {
                var packetInfo = _packets[index];
                if (packetInfo.IsServer)
                {
                    // TODO: Make configurable?
                    if (packetInfo.IsValid)
                    {
                        server.Send(packetInfo.Data, packetInfo.Data.Length, sender);

                        _packetIndex = index;
                    }
                    else
                    {
                        Console.WriteLine($"Packet {_packetIndex} was not valid, attempting to send previous valid packet...");

                        var foundValid = false; // TODO: Add later.

                        for (var _index = _packetIndex; _index < _packets.Count - 1; _index--)
                        {
                            var _packetInfo = _packets[_index];
                            if (_packetInfo.IsServer)
                            {
                                if (_packetInfo.IsValid)
                                {
                                    foundValid = true;

                                    Console.WriteLine($"Packet {_index} was valid, sent packet.");

                                    server.Send(packetInfo.Data, packetInfo.Data.Length, sender);

                                    break;
                                }
                            }
                        }

                        _packetIndex = index;
                    }
                }

                // If the next packet is from the client, stop the for loop.
                // Otherwise, continue the for loop so that we can send the next server packet.
                if (!_packets[index + 1].IsServer)
                    break;
            }
        }

        private static byte[] RemoveTrailing(byte[] value)
        {
            var index = value.Length - 1;

            while (value[index] == 0)
                --index;

            var result = new byte[index + 1];
            Array.Copy(value, result, index + 1);

            return result;
        }

        private static void OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (e.Packet.LinkLayerType == LinkLayers.Ethernet)
            {
                var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ethernet = (EthernetPacket)packet;

                if (ethernet.PayloadPacket.PayloadPacket.HasPayloadData)
                {
                    var isValid = true;

                    using (MemoryStream stream = new MemoryStream(e.Packet.Data))
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        stream.Seek(0x26, SeekOrigin.Begin);

                        var _length = reader.ReadBytes(2);
                        Array.Reverse(_length);

                        var length = BitConverter.ToUInt16(_length, 0);
                        if (length != ethernet.PayloadPacket.PayloadPacket.PayloadData.Length + 8)
                        {
                            Console.WriteLine($"Packet {_packetIndex} has failed length check, this packet will be ignored.");
                            Console.WriteLine($"    Expected Length = {length}, Actual Length = {ethernet.PayloadPacket.PayloadPacket.PayloadData.Length}");

                            isValid = false;
                        }
                    }

                    _packets.Add(_packetIndex, new PacketInfo()
                    {
                        Data = RemoveTrailing(ethernet.PayloadPacket.PayloadPacket.PayloadData),

                        IsServer = ethernet.SourceHardwareAddress.ToString() != _clientMacAddress,
                        IsValid = isValid
                    });

                    _packetIndex++;
                }
            }
        }
    }
}
