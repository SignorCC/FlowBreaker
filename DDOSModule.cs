using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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
            var synFloodTask = DetectSYNFloodAsync(tcpDestination, settings.GetValue<SYNFloodConfig>("SYNFlood"), sslLogs);
            var udpFloodTask = DetectUDPFloodAsync(udpDestination, settings.GetValue<UDPFloodConfig>("UDPFlood"), dnsLogs);
            var icmpFloodTask = DetectICMPFloodAsync(icmpDestination, settings.GetValue<ICMPFloodConfig>("ICMPFlood"));
            var dnsAmplificationTask = DetectDNSAmplificationAsync(udpSource, settings.GetValue<DNSAmplificationConfig>("DNSAmplification"), dnsLogs);
            var ntpAmplificationTask = DetectNTPAmplificationAsync(udpSource, settings.GetValue<NTPAmplificationConfig>("NTPAmplification"));
            var ssdpAmplificationTask = DetectSSDPAmplificationAsync(udpSource, settings.GetValue<SSDPAmplificationConfig>("SSDPAmplification"));
            var connectionExhaustionTask = DetectConnectionExhaustionAsync(tcpDestination, settings.GetValue<ConnectionExhaustionConfig>("ConnectionExhaustion"), httpLogs);
            var slowlorisTask = DetectSlowlorisAttackAsync(tcpDestination, settings.GetValue<SlowlorisConfig>("Slowloris"), httpLogs);

            await Task.WhenAll(synFloodTask, udpFloodTask, icmpFloodTask, dnsAmplificationTask, ntpAmplificationTask,
                ssdpAmplificationTask, connectionExhaustionTask, slowlorisTask);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["SYNFlood"] = await synFloodTask,
                ["UDPFlood"] = await udpFloodTask,
                ["ICMPFlood"] = await icmpFloodTask,
                ["DNSAmplification"] = await dnsAmplificationTask,
                ["NTPAmplification"] = await ntpAmplificationTask,
                ["SSDPAmplification"] = await ssdpAmplificationTask,
                ["ConnectionExhaustion"] = await connectionExhaustionTask,
                ["Slowloris"] = await slowlorisTask
            };
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectSYNFloodAsync(
            Dictionary<string, ConnectionGroup> input, SYNFloodConfig config, List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var synConnections = kvp.Value.connections.Count(c => c.history == "S");
                    var failedSSLHandshakes = sslLogs.Count(s => kvp.Value.connections.Any(c => c.uid == s.uid) && !s.established);

                    if (synConnections + failedSSLHandshakes >= config.SYNThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SYN Flood";
                        cG.reason = $"High number of SYN packets: {synConnections}, Failed SSL handshakes: {failedSSLHandshakes}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectUDPFloodAsync(
            Dictionary<string, ConnectionGroup> input, UDPFloodConfig config, List<DNSConnection> dnsLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var udpConnections = kvp.Value.connections.Count;
                    var dnsQueries = dnsLogs.Count(d => kvp.Value.connections.Any(c => c.uid == d.uid));

                    if (udpConnections >= config.UDPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "UDP Flood";
                        cG.reason = $"High number of UDP packets: {udpConnections}, DNS queries: {dnsQueries}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectICMPFloodAsync(
            Dictionary<string, ConnectionGroup> input, ICMPFloodConfig config)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    if (kvp.Value.connections.Count >= config.ICMPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "ICMP Flood";
                        cG.reason = $"High number of ICMP packets: {kvp.Value.connections.Count}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectDNSAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, DNSAmplificationConfig config, List<DNSConnection> dnsLogs)
        {
            // This method works on detecting redundant DNS queries, for which 2 conditions must be met:
            // The total number of DNS queries >= DNSThreshold and the number of queries for a single domain >= MaxDomainRepetitions
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    string ip = kvp.Key;
                    var dnsResponses = dnsLogs.Where(log => log.id_orig_h == ip).ToList();

                    if (dnsResponses.Count >= config.DNSThreshold)
                    {
                        var redundantQueries = dnsResponses
                            .GroupBy(d => d.query ?? "Unknown")
                            .Where(g => g.Count() >= config.MaxDomainRepetitions)
                            .ToDictionary(g => g.Key, g => g.Count());


                        var totalAnswers = redundantQueries.Sum(kvp => kvp.Value);

                        if (redundantQueries.Any())
                        {
                            var cG = kvp.Value.Copy();
                            cG.classification = "DNS Amplification";

                            string domains = string.Join("\n", redundantQueries.Select(kvp => $"\t\t{kvp.Key} ({kvp.Value})"));

                            cG.reason = $"\tTotal DNS requests: {dnsResponses.Count} (Threshold: {config.DNSThreshold})\n\tDomains:\n{domains}";
                            cG.reason += $"\n\tTotal redundant Queries: {totalAnswers} (Threshold: {config.MaxDomainRepetitions})";
                            output[ip] = cG;
                        }
                    }
                }

                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectNTPAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, NTPAmplificationConfig config)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var ntpConnections = kvp.Value.connections.Where(c => c.id_resp_p == 123).ToList();
                    if (ntpConnections.Count >= config.NTPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "NTP Amplification";
                        cG.reason = $"Potential NTP amplification attack detected";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectSSDPAmplificationAsync(
            Dictionary<string, ConnectionGroup> input, SSDPAmplificationConfig config)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var ssdpConnections = kvp.Value.connections.Where(c => c.id_resp_p == 1900).ToList();
                    if (ssdpConnections.Count >= config.SSDPThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSDP Amplification";
                        cG.reason = $"Potential SSDP amplification attack detected";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectConnectionExhaustionAsync(
            Dictionary<string, ConnectionGroup> input, ConnectionExhaustionConfig config, List<HTTPConnection> httpLogs)
        {
            // This method works by checking for a high number of connections with minimal data transfer that stay open for long
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var totalConnections = kvp.Value.connections.Where(c => c.orig_bytes + c.resp_bytes <= config.MaxBytes && c.duration >= config.MinDuration);

                    if (totalConnections.Count() >= config.ConnectionThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Connection Exhaustion";
                        cG.reason = $"High number of connections with small data (<={config.MaxBytes}) but long duration >= {config.MinDuration}: Total: {totalConnections.Count()}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectSlowlorisAttackAsync(
            Dictionary<string, ConnectionGroup> input, SlowlorisConfig config, List<HTTPConnection> httpLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var halfOpenConnections = kvp.Value.connections.Count(c => c.conn_state == "S1" || c.conn_state == "SF" && c.duration >= config.MinDuration);
                    var suspiciousHTTPConnections = httpLogs.Count(h => kvp.Value.connections.Any(c => c.uid == h.uid) &&
                                                                        (h.method == "GET" || h.method == "POST") &&
                                                                        h.request_body_len == 0);

                    if (halfOpenConnections + suspiciousHTTPConnections >= config.HalfOpenThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Slowloris Attack";
                        cG.reason = $"High number of half-open connections: {halfOpenConnections}, " +
                                    $"Suspicious HTTP connections: {suspiciousHTTPConnections}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

    }
}