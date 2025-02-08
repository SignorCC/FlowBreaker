using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace FlowBreaker
{
    public static class ScanningModule
    {
        public static async Task<Dictionary<string, Dictionary<string, ConnectionGroup>>> ExecuteModuleAsync(
            Dictionary<string, ConnectionGroup> sortByDestination,
            Dictionary<string, ConnectionGroup> sortBySource,
            Configuration settings,
            List<SSHConnection> sshLogs,
            List<DNSConnection> dnsLogs,
            List<SSLConnection> sslLogs,
            List<HTTPConnection> httpLogs)
        {
            // Pre-process logs for faster lookups
            var sshLogDict = sshLogs.GroupBy(s => s.uid).ToDictionary(g => g.Key, g => g.First());
            var dnsLogDict = dnsLogs.GroupBy(d => d.uid).ToDictionary(g => g.Key, g => g.ToList());
            var sslLogDict = sslLogs.GroupBy(s => s.uid).ToDictionary(g => g.Key, g => g.First());
            var httpLogDict = httpLogs.GroupBy(h => h.uid).ToDictionary(g => g.Key, g => g.First());

            var portScanConfig = settings.GetValue<PortScanConfig>("PortScan");
            var versionScanConfig = settings.GetValue<VersionScanConfig>("VersionScan");
            var hostDiscoveryScanConfig = settings.GetValue<HostDiscoveryScanConfig>("HostDiscoveryScan");
            var protocolSpecificScanConfig = settings.GetValue<ProtocolSpecificScanConfig>("ProtocolSpecificScan");
            var serviceEnumerationConfig = settings.GetValue<ServiceEnumerationConfig>("ServiceEnumeration");

            var tasks = new[]
            {
                DetectPortScansAsync(sortBySource, portScanConfig, sshLogDict, sslLogDict),
                DetectVersionScansAsync(sortBySource, versionScanConfig, sshLogDict, sslLogDict),
                DetectHostDiscoveryScansAsync(sortBySource, hostDiscoveryScanConfig, dnsLogDict),
                DetectProtocolSpecificScansAsync(sortBySource, protocolSpecificScanConfig, sslLogDict),
                DetectServiceEnumerationAsync(sortBySource, serviceEnumerationConfig, httpLogDict)
            };

            await Task.WhenAll(tasks);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["PortScans"] = await tasks[0],
                ["VersionScans"] = await tasks[1],
                ["HostDiscoveryScans"] = await tasks[2],
                ["ProtocolSpecificScans"] = await tasks[3],
                ["ServiceEnumeration"] = await tasks[4],
            };
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectPortScansAsync(
            Dictionary<string, ConnectionGroup> input,
            PortScanConfig config,
            Dictionary<string, SSHConnection> sshLogs,
            Dictionary<string, SSLConnection> sslLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();

                Parallel.ForEach(input, kvp =>
                {
                    if (kvp.Value.dest_ports.Count >= config.Unique_Port_Threshold)
                    {
                        var rejected = kvp.Value.connections.Where(c => c.conn_state == "S0" || c.conn_state == "REJ" || c.conn_state == "RSTOS0" || c.conn_state == "RSTRH").ToList();
                        var s0 = rejected.Count(c => c.conn_state == "S0");
                        var rej = rejected.Count(c => c.conn_state == "REJ");
                        var rstos0 = rejected.Count(c => c.conn_state == "RSTOS0");
                        var rstrh = rejected.Count(c => c.conn_state == "RSTRH");

                        var sshAttempts = kvp.Value.connections.Count(c => sshLogs.TryGetValue(c.uid, out var ssh) && ssh.auth_attempts > 0);
                        var sslAttempts = kvp.Value.connections.Count(c => sslLogs.TryGetValue(c.uid, out var ssl) && !ssl.established);

                        if (rejected.Count >= config.Connection_Threshold)
                        {
                            var cG = kvp.Value.Copy();
                            cG.classification = "Port Scan";
                            cG.reason = $"More than {config.Connection_Threshold} (total: {rejected.Count}) bad connections to more than {config.Unique_Port_Threshold} different ports\nStates:\n" +
                                        $"S0 (no answer) {s0}\n" +
                                        $"REJ (rejected) {rej}\n" +
                                        $"RSTOS0 (syn followed by reset) {rstos0}\n" +
                                        $"RSTRH (SYN_ACK followed by RST, SYN wasn't seen) {rstrh}\n" +
                                        $"Failed SSH attempts: {sshAttempts}\n" +
                                        $"Failed SSL attempts: {sslAttempts}";

                            output[kvp.Key] = cG;
                        }
                    }
                });

                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectVersionScansAsync(
            Dictionary<string, ConnectionGroup> input,
            VersionScanConfig config,
            Dictionary<string, SSHConnection> sshLogs,
            Dictionary<string, SSLConnection> sslLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();

                Parallel.ForEach(input, kvp =>
                {
                    var commonPortConnections = kvp.Value.connections
                        .Where(c => config.Common_Ports.Contains(c.id_resp_p) &&
                                    (c.orig_ip_bytes + c.resp_ip_bytes) <= config.Max_Bytes_Transferred)
                        .ToList();

                    var enhancedConnections = commonPortConnections.Select(c => new
                    {
                        Connection = c,
                        SSHInfo = sshLogs.TryGetValue(c.uid, out var ssh) ? ssh : null,
                        SSLInfo = sslLogs.TryGetValue(c.uid, out var ssl) ? ssl : null
                    }).ToList();

                    var portCounts = enhancedConnections
                        .GroupBy(c => c.Connection.id_resp_p)
                        .Select(g => new { Port = g.Key, Count = g.Count() })
                        .Where(pc => pc.Count >= config.Connection_Threshold)
                        .ToList();

                    if (portCounts.Count >= config.Min_Port_Number)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Version Scan";
                        cG.reason = $"Multiple short connections to common ports with minimal data transfer:\n" +
                                    $"\tSaw: {portCounts.Count} ports with >= {config.Connection_Threshold} connections each " +
                                    $"(threshold: {config.Min_Port_Number} ports, <= {config.Max_Bytes_Transferred} Bytes per connection)\n" +
                                    $"Ports: {string.Join(", ", portCounts.Select(pc => $"{pc.Port} ({pc.Count} conns)"))}\n" +
                                    $"Includes {enhancedConnections.Count(c => c.SSHInfo != null)} SSH and {enhancedConnections.Count(c => c.SSLInfo != null)} SSL connections";

                        output[kvp.Key] = cG;
                    }
                });

                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectHostDiscoveryScansAsync(
            Dictionary<string, ConnectionGroup> input,
            HostDiscoveryScanConfig config,
            Dictionary<string, List<DNSConnection>> dnsLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();

                Parallel.ForEach(input, kvp =>
                {
                    var uniqueDestIPs = kvp.Value.connections
                        .Select(c => c.id_resp_h)
                        .Distinct()
                        .Count();

                    var uniqueDNSQueries = kvp.Value.connections
                        .Where(c => dnsLogs.TryGetValue(c.uid, out var dnsLog))
                        .SelectMany(c => dnsLogs[c.uid].Select(d => d.query))
                        .Distinct()
                        .Count();

                    if (uniqueDestIPs >= config.Unique_IP_Threshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Host Discovery Scan";
                        cG.reason = $"Connections to multiple destination IPs and DNS queries:\n" +
                                    $"\tUnique Destination IPs: {uniqueDestIPs}\n" +
                                    $"\tUnique DNS Queries: {uniqueDNSQueries}";

                        output[kvp.Key] = cG;
                    }
                });

                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectProtocolSpecificScansAsync(
            Dictionary<string, ConnectionGroup> input,
            ProtocolSpecificScanConfig config,
            Dictionary<string, SSLConnection> sslLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();

                Parallel.ForEach(input, kvp =>
                {
                    var synScans = kvp.Value.connections.Count(c => c.history == "S");
                    var sslHandshakes = kvp.Value.connections.Count(c => sslLogs.TryGetValue(c.uid, out var ssl) && !ssl.established);

                    if (synScans >= config.SYN_Scan_Threshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Protocol-Specific Scan";
                        cG.reason = $"Multiple protocol-specific connection attempts:\n" +
                                    $"\tSYN-only connections: {synScans}\n" +
                                    $"\tFailed SSL handshakes: {sslHandshakes}";

                        output[kvp.Key] = cG;
                    }
                });

                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectServiceEnumerationAsync(
            Dictionary<string, ConnectionGroup> input,
            ServiceEnumerationConfig config,
            Dictionary<string, HTTPConnection> httpLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();

                Parallel.ForEach(input, kvp =>
                {
                    var serviceConnections = kvp.Value.connections
                        .Where(c => config.Common_Ports.Contains(c.id_resp_p) &&
                                    (c.orig_ip_bytes + c.resp_ip_bytes) >= config.Min_Bytes_Transferred)
                        .ToList();

                    var enhancedConnections = serviceConnections.Select(c => new
                    {
                        Connection = c,
                        HTTPInfo = httpLogs.TryGetValue(c.uid, out var http) ? http : null
                    }).ToList();

                    var portCounts = enhancedConnections
                        .GroupBy(c => c.Connection.id_resp_p)
                        .Select(g => new { Port = g.Key, Count = g.Count() })
                        .Where(pc => pc.Count >= config.Connection_Threshold)
                        .ToList();

                    if (portCounts.Count >= config.Min_Port_Number)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Service Enumeration";
                        cG.reason = $"Multiple connections to common ports with data transfer:\n" +
                                    $"\tSaw: {portCounts.Count} ports with >= {config.Connection_Threshold} connections each " +
                                    $"(threshold: {config.Min_Port_Number} ports, {config.Min_Bytes_Transferred} Bytes per connection)\n" +
                                    $"Ports: {string.Join(", ", portCounts.Select(pc => $"{pc.Port} ({pc.Count} conns)"))}\n" +
                                    $"Includes {enhancedConnections.Count(c => c.HTTPInfo != null)} HTTP connections";

                        output[kvp.Key] = cG;
                    }
                });

                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }
    }
}