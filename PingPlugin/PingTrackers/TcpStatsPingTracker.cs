using Dalamud.Plugin.Services;
using PingPlugin.GameAddressDetectors;
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PingPlugin.PingTrackers
{
    // Measures RTT from the active FFXIV TCP connection using Windows TCP extended stats.
    // Works through VPNs where ICMP-based methods fail.
    public class TcpStatsPingTracker : PingTracker
    {
        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
        private const int MIB_TCP_STATE_ESTAB = 5;

        private const ushort XIV_MIN_PORT_1 = 54992;
        private const ushort XIV_MAX_PORT_1 = 54994;
        private const ushort XIV_MIN_PORT_2 = 55006;
        private const ushort XIV_MAX_PORT_2 = 55007;
        private const ushort XIV_MIN_PORT_3 = 55021;
        private const ushort XIV_MAX_PORT_3 = 55040;
        private const ushort XIV_MIN_PORT_4 = 55296;
        private const ushort XIV_MAX_PORT_4 = 55551;

        private readonly IPluginLog pluginLog;

        public TcpStatsPingTracker(PingConfiguration config, GameAddressDetector addressDetector, IPluginLog pluginLog)
            : base(config, addressDetector, PingTrackerKind.TcpStats, pluginLog)
        {
            this.pluginLog = pluginLog;
        }

        protected override async Task PingLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (TryGetXivTcpRtt(out var rttMs))
                    {
                        Errored = false;
                        NextRTTCalculation(rttMs);
                    }
                    else
                    {
                        Errored = true;
                    }
                }
                catch (Exception e)
                {
                    Errored = true;
                    pluginLog.Error(e, "Error in TCP stats RTT measurement.");
                }

                await Task.Delay(3000, token);
            }
        }

        private bool TryGetXivTcpRtt(out ulong rttMs)
        {
            rttMs = 0;

            var bufferLength = 0;
            _ = GetExtendedTcpTable(IntPtr.Zero, ref bufferLength, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS);
            var pTcpTable = Marshal.AllocHGlobal(bufferLength);

            try
            {
                var error = GetExtendedTcpTable(pTcpTable, ref bufferLength, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS);
                if (error != 0) return false;

                var pid = Environment.ProcessId;
                var rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
                var dwNumEntries = Marshal.ReadInt32(pTcpTable);
                var pRows = pTcpTable + 4;

                for (var i = 0; i < dwNumEntries; i++)
                {
                    var row = Marshal.PtrToStructure<TcpRowOwnerPid>(pRows + i * rowSize);
                    if ((int)row.dwOwningPid != pid) continue;
                    if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

                    var remoteAddr = new IPAddress(row.dwRemoteAddr);
                    if (Equals(remoteAddr, IPAddress.Loopback)) continue;

                    var remotePort = BitConverter.ToUInt16(new[] { (byte)(row.dwRemotePort >> 8), (byte)row.dwRemotePort });
                    if (!InXIVPortRange(remotePort)) continue;

                    // Found an established FFXIV TCP connection — query its path stats for RTT
                    var tcpRow = new MibTcpRow
                    {
                        dwState = row.dwState,
                        dwLocalAddr = row.dwLocalAddr,
                        dwLocalPort = row.dwLocalPort,
                        dwRemoteAddr = row.dwRemoteAddr,
                        dwRemotePort = row.dwRemotePort,
                    };

                    var rodSize = Marshal.SizeOf<TcpEstatsPathRodV0>();
                    var pRod = Marshal.AllocHGlobal(rodSize);
                    try
                    {
                        // Zero out the struct before passing
                        for (var b = 0; b < rodSize; b++)
                            Marshal.WriteByte(pRod, b, 0);

                        var result = GetPerTcpConnectionEStats(
                            ref tcpRow,
                            TcpConnectionEstatsType.TcpConnectionEstatsPath,
                            IntPtr.Zero, 0, 0,
                            IntPtr.Zero, 0, 0,
                            pRod, 0, (uint)rodSize);

                        if (result == 0)
                        {
                            var rod = Marshal.PtrToStructure<TcpEstatsPathRodV0>(pRod);
                            // SampleRtt is in milliseconds; 0 means no sample yet
                            if (rod.SampleRtt > 0 && rod.SampleRtt < 60000)
                            {
                                rttMs = rod.SampleRtt;
                                return true;
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pRod);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pTcpTable);
            }

            return false;
        }

        private static bool InXIVPortRange(ushort port) =>
            (port >= XIV_MIN_PORT_1 && port <= XIV_MAX_PORT_1) ||
            (port >= XIV_MIN_PORT_2 && port <= XIV_MAX_PORT_2) ||
            (port >= XIV_MIN_PORT_3 && port <= XIV_MAX_PORT_3) ||
            (port >= XIV_MIN_PORT_4 && port <= XIV_MAX_PORT_4);

        private enum TcpConnectionEstatsType
        {
            TcpConnectionEstatsPath = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRow
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TcpRowOwnerPid
        {
            public readonly uint dwState;
            public readonly uint dwLocalAddr;
            public readonly uint dwLocalPort;
            public readonly uint dwRemoteAddr;
            public readonly uint dwRemotePort;
            public readonly uint dwOwningPid;
        }

        // TCP_ESTATS_PATH_ROD_v0 — only fields we care about, rest padded
        [StructLayout(LayoutKind.Sequential)]
        private struct TcpEstatsPathRodV0
        {
            public uint FastRetran;
            public uint Timeouts;
            public uint SubsequentTimeouts;
            public uint CurTimeoutCount;
            public uint AbruptTimeouts;
            public uint PktsRetrans;
            public uint BytesRetrans;
            public uint DupAcksIn;
            public uint SacksRcvd;
            public uint SackBlocksRcvd;
            public uint CongSignals;
            public uint PreCongSumCwnd;
            public uint PreCongSumRtt;
            public uint PostCongSumRtt;
            public uint PostCongCountRtt;
            public uint EcnSignals;
            public uint EceRcvd;
            public uint SendStall;
            public uint QuenchRcvd;
            public uint RetranThresh;
            public uint SndDupAckEpisodes;
            public uint SumBytesReordered;
            public uint NonRecovDa;
            public uint NonRecovDaEpisodes;
            public uint AckAfterFr;
            public uint DsackDups;
            public uint SampleRtt;      // milliseconds
            public uint SmoothedRtt;    // milliseconds
            public uint RttVar;
            public uint MaxRtt;
            public uint MinRtt;
            public uint SumRtt;
            public uint CountRtt;
            public uint CurRto;
            public uint MaxRto;
            public uint MinRto;
            public uint CurMss;
            public uint SpuriousRtoDetections;
        }

        [DllImport("Iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
            int ipVersion, int tblClass, uint reserved = 0);

        [DllImport("Iphlpapi.dll", SetLastError = true)]
        private static extern uint GetPerTcpConnectionEStats(
            ref MibTcpRow Row,
            TcpConnectionEstatsType EstatsType,
            IntPtr Rw, uint RwVersion, uint RwSize,
            IntPtr Ros, uint RosVersion, uint RosSize,
            IntPtr Rod, uint RodVersion, uint RodSize);
    }
}
