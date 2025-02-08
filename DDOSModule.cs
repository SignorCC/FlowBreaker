using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace FlowBreaker
{
    public static class DDOSModule
    {
        public static async Task<Dictionary<string, Dictionary<string, ConnectionGroup>>> ExecuteModuleAsync(
            Dictionary<string, ConnectionGroup> tcpDestination,
            Dictionary<string, ConnectionGroup> tcpSource,
            Dictionary<string, ConnectionGroup> udpDestination,
            Dictionary<string, ConnectionGroup> udpSource,
            Dictionary<string, ConnectionGroup> icmpDestination,
            Dictionary<string, ConnectionGroup> icmpSource,
            Configuration settings,
            List<SSHConnection> sshLogs,
            List<DNSConnection> dnsLogs,
            List<SSLConnection> sslLogs,
            List<HTTPConnection> httpLogs)
        {
            // Pre-process logs for faster lookups
            var sslLogSet = new HashSet<string>(sslLogs.Where(s => !s.established).Select(s => s.uid));
            var dnsLogDict = dnsLogs.GroupBy(d => d.id_resp_h).ToDictionary(g => g.Key, g => g.ToList());
            var httpLogDict = httpLogs.GroupBy(h => h.uid).ToDictionary(g => g.Key, g => g.First());

            var tasks = new[]
            {
                DetectSYNFloodAsync(tcpDestination, settings.GetValue<SYNFloodConfig>("SYNFlood"), sslLogSet),
                DetectUDPFloodAsync(udpDestination, settings.GetValue<UDPFloodConfig>("UDPFlood"), dnsLogDict),
                DetectICMPFloodAsync(icmpDestination, settings.GetValue<ICMPFloodConfig>("ICMPFlood")),
                DetectDNSAmplificationAsync(udpSource, settings.GetValue<DNSAmplificationConfig>("DNSAmplification"), dnsLogDict),
                DetectNTPAmplificationAsync(udpSource, settings.GetValue<NTPAmplificationConfig>("NTPAmplification")),
                DetectSSDPAmplificationAsync(udpSource, settings.GetValue<SSDPAmplificationConfig>("SSDPAmplification")),
                DetectConnectionExhaustionAsync(tcpDestination, settings.GetValue<ConnectionExhaustionConfig>("ConnectionExhaustion")),
                DetectSlowlorisAttackAsync(tcpDestination, settings.GetValue<SlowlorisConfig>("Slowloris"), httpLogDict)
            };

            await Task.WhenAll(tasks);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["SYNFlood"] = await tasks[0],
                ["UDPFlood"] = await tasks[1],
                ["ICMPFlood"] = await tasks[2],
                ["DNSAmplification"] = await tasks[3],
                ["NTPAmplification"] = await tasks[4],
                ["SSDPAmplification"] = await tasks[5],
                ["ConnectionExhaustion"] = await tasks[6],
                ["Slowloris"] = await tasks[7]
            };
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectSYNFloodAsync(
            Dictionary<string, ConnectionGroup> input, SYNFloodConfig config, HashSet<string> failedSslHandshakes)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var synConnections = kvp.Value.connections.Count(c => c.history == "S");
                    var failedSSLHandshakes = kvp.Value.connections.Count(c => failedSslHandshakes.Contains(c.uid));

                    if (synConnections + failedSSLHandshakes >= config.SYNThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SYN Flood";
                        cG.reason = $"High number of SYN packets: {synConnections}, Failed SSL handshakes: {failedSSLHandshakes}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectUDPFloodAsync(
            Dictionary<string, ConnectionGroup> input, UDPFloodConfig config, Dictionary<string, List<DNSConnection>> dnsLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var udpConnections = kvp.Value.connections.Count;
                    var dnsQueries = dnsLogs.TryGetValue(kvp.Key, out var logs) ? logs.Count : 0;

                    if (udpConnections >= config.UDPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "UDP Flood";
                        cG.reason = $"High number of UDP connections: {udpConnections}, DNS queries: {dnsQueries}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectICMPFloodAsync(
            Dictionary<string, ConnectionGroup> input, ICMPFloodConfig config)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    if (kvp.Value.connections.Count >= config.ICMPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "ICMP Flood";
                        cG.reason = $"High number of ICMP connections: {kvp.Value.connections.Count}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectDNSAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, DNSAmplificationConfig config, Dictionary<string, List<DNSConnection>> dnsLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    string ip = kvp.Key;
                    if (dnsLogs.TryGetValue(ip, out var dnsResponses) && dnsResponses.Count >= config.DNSThreshold)
                    {
                        var redundantQueries = dnsResponses
                            .GroupBy(d => d.query ?? "Unknown")
                            .Where(g => g.Count() >= config.MaxDomainRepetitions)
                            .ToDictionary(g => g.Key, g => g.Count());

                        if (redundantQueries.Any())
                        {
                            var cG = kvp.Value.Copy();
                            cG.classification = "DNS Amplification";
                            string domains = string.Join("\n", redundantQueries.Select(kvp => $"\t\t{kvp.Key} ({kvp.Value})"));
                            cG.reason = $"\tTotal DNS requests: {dnsResponses.Count} (Threshold: {config.DNSThreshold})\n\tDomains:\n{domains}";
                            cG.reason += $"\n\tTotal redundant Queries: {redundantQueries.Values.Sum()} (Threshold: {config.MaxDomainRepetitions})";
                            output[ip] = cG;
                        }
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectNTPAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, NTPAmplificationConfig config)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var ntpConnections = kvp.Value.connections.Count(c => c.id_resp_p == 123);
                    if (ntpConnections >= config.NTPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "NTP Amplification";
                        cG.reason = $"Potential NTP amplification attack detected. NTP connections: {ntpConnections}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectSSDPAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, SSDPAmplificationConfig config)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var ssdpConnections = kvp.Value.connections.Count(c => c.id_resp_p == 1900);
                    if (ssdpConnections >= config.SSDPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSDP Amplification";
                        cG.reason = $"Potential SSDP amplification attack detected. SSDP connections: {ssdpConnections}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectConnectionExhaustionAsync(
            Dictionary<string, ConnectionGroup> input, ConnectionExhaustionConfig config)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var totalConnections = kvp.Value.connections.Count(c => c.orig_ip_bytes + c.resp_ip_bytes <= config.MaxBytes && c.duration >= config.MinDuration);

                    if (totalConnections >= config.ConnectionThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Connection Exhaustion";
                        cG.reason = $"High number of connections with small data (<={config.MaxBytes}) but long duration >= {config.MinDuration}: Total: {totalConnections}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectSlowlorisAttackAsync(
            Dictionary<string, ConnectionGroup> input, SlowlorisConfig config, Dictionary<string, HTTPConnection> httpLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var halfOpenConnections = kvp.Value.connections.Count(c => c.conn_state == "S1" || (c.conn_state == "SF" && c.duration >= config.MinDuration));
                    var suspiciousHTTPConnections = kvp.Value.connections.Count(c =>
                        httpLogs.TryGetValue(c.uid, out var httpConn) &&
                        (httpConn.method == "GET" || httpConn.method == "POST") &&
                        httpConn.request_body_len == 0);

                    if (halfOpenConnections + suspiciousHTTPConnections >= config.HalfOpenThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Slowloris Attack";
                        cG.reason = $"High number of half-open connections: {halfOpenConnections}, " +
                                    $"Suspicious HTTP connections: {suspiciousHTTPConnections}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }
    }
}