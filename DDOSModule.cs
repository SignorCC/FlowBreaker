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
            var sslLogSet = new HashSet<string>(sslLogs?.Where(s => !s.established).Select(s => s.uid ?? string.Empty) ?? Enumerable.Empty<string>());

            var dnsLogDict = dnsLogs?
                .Where(d => d.id_resp_h != null)
                .GroupBy(d => d.id_resp_h)
                .ToDictionary(g => g.Key, g => g.ToList())
                ?? new Dictionary<string, List<DNSConnection>>();

            var httpLogDict = httpLogs?
                .Where(h => h.uid != null)
                .GroupBy(h => h.uid)
                .ToDictionary(g => g.Key, g => g.FirstOrDefault())
                ?? new Dictionary<string, HTTPConnection>();

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
                    var synConnections = kvp.Value.connections.Where(c => c.conn_state == "S0" || c.conn_state == "REJ").ToList();


                    if (synConnections.Count() >= config.SYNThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SYN Flood";
                        cG.reason = $"High number of connections in S0 or REJ state: {synConnections.Count} (threshold: {config.SYNThreshold})";

                        cG.resetConnections(synConnections);
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

                    if (ip != null && dnsLogs != null && dnsLogs.TryGetValue(ip, out var dnsResponses) && dnsResponses != null && dnsResponses.Count >= config.DNSThreshold)
                    {
                        if (config.MaxDomainRepetitions == 0)
                        {
                            var cG = kvp.Value.Copy();

                            cG.classification = "DNS Amplification";
                            cG.reason = $"\tTotal DNS requests: {dnsResponses.Count} (Threshold: {config.DNSThreshold}), MaxDomainRepetitions set to 0";

                            var newConnections = cG.connections.Where(c => c != null && dnsResponses.Any(d => d != null && d.uid == c.uid)).ToList();

                            if (newConnections.Count >= 1)
                                cG.resetConnections(newConnections);

                            output[ip] = cG;
                        }
                        else
                        {
                            Dictionary<string, int> redundantQueries = new Dictionary<string, int>();

                            foreach (var dnsResponse in dnsResponses.Where(d => d != null && d.query != null))
                            {
                                if (redundantQueries.ContainsKey(dnsResponse.query))
                                    redundantQueries[dnsResponse.query]++;
                                else
                                    redundantQueries[dnsResponse.query] = 1;
                            }

                            // Search for redundant queries
                            redundantQueries = redundantQueries.Where(kvp => kvp.Value >= config.MaxDomainRepetitions).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                            if (redundantQueries.Count >= config.DNSThreshold)
                            {
                                var cG = kvp.Value.Copy();
                                cG.classification = "DNS Amplification";
                                cG.reason = $"\tTotal repeated DNS Queries: {redundantQueries.Count} (Threshold: {config.DNSThreshold})";
                                cG.reason += $"\n\tAbove mentioned Queries have been repeated more than > {config.MaxDomainRepetitions} times";
                                cG.reason += $"\n\tTotal redundant Requests: {redundantQueries.Values.Sum()}";

                                var newConnections = cG.connections.Where(c => c != null && dnsResponses.Any(d => d != null && d.uid == c.uid)).ToList();

                                if (newConnections.Count >= 1)
                                    cG.resetConnections(newConnections);

                                output[ip] = cG;
                            }
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

                        cG.resetConnections(cG.connections.Where(c => c.id_resp_p == 123).ToList());
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

                        cG.resetConnections(cG.connections.Where(c => c.id_resp_p == 1900).ToList());
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
                    var totalConnections = kvp.Value.connections.Where(c => c.orig_ip_bytes + c.resp_ip_bytes <= config.MaxBytes && c.duration >= config.MinDuration).ToList();

                    if (totalConnections.Count >= config.ConnectionThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Connection Exhaustion";
                        cG.reason = $"High number of connections with small data (<={config.MaxBytes}) but long duration >= {config.MinDuration}: Total: {totalConnections.Count}";

                        cG.resetConnections(totalConnections);
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
                    var halfOpenConnections = kvp.Value.connections.Where(c => c.conn_state == "S1" || (c.conn_state == "SF" && c.duration >= config.MinDuration)).ToList();
                    var suspiciousHTTPConnections = kvp.Value.connections.Where(c =>
                        httpLogs.TryGetValue(c.uid, out var httpConn) &&
                        (httpConn.method == "GET" || httpConn.method == "POST") &&
                        httpConn.request_body_len == 0).ToList();
                                        
                    if (halfOpenConnections.Count + suspiciousHTTPConnections.Count >= config.HalfOpenThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Slowloris Attack";
                        cG.reason = $"High number of half-open connections: {halfOpenConnections.Count}, " +
                                    $"Suspicious HTTP connections: {suspiciousHTTPConnections.Count}";

                        cG.resetConnections(halfOpenConnections.Concat(suspiciousHTTPConnections).ToList());
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }
    }
}