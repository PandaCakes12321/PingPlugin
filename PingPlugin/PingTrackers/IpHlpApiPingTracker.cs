using Dalamud.Logging;
using PingPlugin.GameAddressDetectors;
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Plugin.Services;

namespace PingPlugin.PingTrackers
{
    public class IpHlpApiPingTracker : PingTracker
    {
        private readonly IPluginLog pluginLog;

        public IpHlpApiPingTracker(PingConfiguration config, GameAddressDetector addressDetector, IPluginLog pluginLog) : base(config, addressDetector, PingTrackerKind.IpHlpApi, pluginLog)
        {
            this.pluginLog = pluginLog;
        }

        protected override async Task PingLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (SeAddress != null)
                {
                    try
                    {
                        var success = TryGetAddressLastRTT(SeAddress, out var rtt);
                        var error = (WinError)Marshal.GetLastWin32Error();

                        // GetRTTAndHopCount returns 0 (false) on failure without always setting a
                        // Win32 error — e.g. when a VPN intercepts routing. Check the return value
                        // explicitly so a silent failure isn't recorded as a valid 0ms reading.
                        Errored = !success || error != WinError.NO_ERROR;

                        if (!Errored)
                        {
                            NextRTTCalculation(rtt);
                        }
                        else
                        {
                            pluginLog.Warning($"Got Win32 error {error} when executing ping - this may be temporary and acceptable.");
                        }
                    }
                    catch (Exception e)
                    {
                        Errored = true;
                        pluginLog.Error(e, "Error occurred when executing ping.");
                    }
                }

                await Task.Delay(3000, token);
            }
        }

        private static bool TryGetAddressLastRTT(IPAddress address, out ulong rtt)
        {
            var addressBytes = address.GetAddressBytes();
            var addressRaw = BitConverter.ToUInt32(addressBytes);

            var hopCount = 0U;
            var rttOut = 0U;

            var success = GetRTTAndHopCount(addressRaw, ref hopCount, 51, ref rttOut) == 1;
            rtt = rttOut;
            return success;
        }

        [DllImport("Iphlpapi.dll", EntryPoint = "GetRTTAndHopCount", SetLastError = true)]
        private static extern int GetRTTAndHopCount(uint address, ref uint hopCount, uint maxHops, ref uint rtt);
    }
}