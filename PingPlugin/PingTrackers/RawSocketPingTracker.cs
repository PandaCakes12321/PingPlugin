using PingPlugin.GameAddressDetectors;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Plugin.Services;

namespace PingPlugin.PingTrackers
{
    // Sends ICMP echo requests via a raw socket, bypassing the Windows COM and IpHlpApi ping APIs.
    // Requires the process to run with sufficient privileges (admin or SeNetworkPrivilege).
    public class RawSocketPingTracker : PingTracker
    {
        private readonly IPluginLog pluginLog;
        private ushort sequenceNumber;

        public RawSocketPingTracker(PingConfiguration config, GameAddressDetector addressDetector, IPluginLog pluginLog)
            : base(config, addressDetector, PingTrackerKind.RawSocket, pluginLog)
        {
            this.pluginLog = pluginLog;
        }

        protected override async Task PingLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (SeAddress != null && !Equals(SeAddress, IPAddress.Loopback))
                {
                    try
                    {
                        var rtt = PingOnce(SeAddress);
                        Errored = rtt == null;
                        if (!Errored)
                            NextRTTCalculation(rtt!.Value);
                    }
                    catch (SocketException ex)
                    {
                        Errored = true;
                        pluginLog.Warning($"RawSocket ping SocketException: {ex.SocketErrorCode} ({ex.NativeErrorCode})");
                    }
                    catch (Exception e)
                    {
                        Errored = true;
                        pluginLog.Error(e, "Error in raw socket ping.");
                    }
                }

                await Task.Delay(3000, token);
            }
        }

        private ulong? PingOnce(IPAddress target)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            socket.ReceiveTimeout = 2000;
            socket.SendTimeout   = 2000;

            var id  = (ushort)(Environment.ProcessId & 0xFFFF);
            var seq = ++this.sequenceNumber;
            var packet = BuildEchoRequest(id, seq);

            var remote = new IPEndPoint(target, 0);
            var sw = Stopwatch.StartNew();

            socket.SendTo(packet, SocketFlags.None, remote);

            var buf       = new byte[1024];
            var remoteEp  = new IPEndPoint(IPAddress.Any, 0) as EndPoint;

            try
            {
                var received = socket.ReceiveFrom(buf, ref remoteEp);
                sw.Stop();

                // IPv4 header is 20 bytes; ICMP reply starts at offset 20
                if (received >= 28
                    && buf[20] == 0   // Type 0 = Echo Reply
                    && buf[21] == 0   // Code 0
                    && (ushort)((buf[24] << 8) | buf[25]) == id
                    && (ushort)((buf[26] << 8) | buf[27]) == seq)
                {
                    return (ulong)sw.ElapsedMilliseconds;
                }
            }
            catch (SocketException)
            {
                // Timed out or no reply
            }

            return null;
        }

        private static byte[] BuildEchoRequest(ushort id, ushort seq)
        {
            var p = new byte[8];
            p[0] = 8; // Echo Request
            p[1] = 0;
            p[2] = 0; // checksum placeholder
            p[3] = 0;
            p[4] = (byte)(id  >> 8);
            p[5] = (byte)(id  & 0xFF);
            p[6] = (byte)(seq >> 8);
            p[7] = (byte)(seq & 0xFF);

            var csum = Checksum(p);
            p[2] = (byte)(csum >> 8);
            p[3] = (byte)(csum & 0xFF);
            return p;
        }

        private static ushort Checksum(byte[] data)
        {
            uint sum = 0;
            for (var i = 0; i < data.Length - 1; i += 2)
                sum += (uint)((data[i] << 8) | data[i + 1]);
            if ((data.Length & 1) == 1)
                sum += (uint)(data[^1] << 8);
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
