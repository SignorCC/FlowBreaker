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
            var portScansTask = DetectPortScansAsync(sortBySource,
                settings.GetValue<PortScanConfig>("PortScan").Connection_Threshold,
                settings.GetValue<PortScanConfig>("PortScan").Unique_Port_Threshold,
                sshLogs, sslLogs);

            var versionScansTask = DetectVersionScansAsync(sortBySource,
                settings.GetValue<VersionScanConfig>("VersionScan").Common_Ports,
                settings.GetValue<VersionScanConfig>("VersionScan").Min_Port_Number,
                settings.GetValue<VersionScanConfig>("VersionScan").Connection_Threshold,
                settings.GetValue<VersionScanConfig>("VersionScan").Max_Bytes_Transferred,
                sshLogs, sslLogs);

            var hostDiscoveryScansTask = DetectHostDiscoveryScansAsync(sortBySource,
                settings.GetValue<HostDiscoveryScanConfig>("HostDiscoveryScan").Unique_IP_Threshold,
                dnsLogs);

            var protocolSpecificScansTask = DetectProtocolSpecificScansAsync(sortBySource,
                settings.GetValue<ProtocolSpecificScanConfig>("ProtocolSpecificScan").SYN_Scan_Threshold,
                sslLogs);

            var serviceEnumerationTask = DetectServiceEnumerationAsync(sortBySource,
                settings.GetValue<ServiceEnumerationConfig>("ServiceEnumeration").Common_Ports,
                settings.GetValue<ServiceEnumerationConfig>("ServiceEnumeration").Min_Port_Number,
                settings.GetValue<ServiceEnumerationConfig>("ServiceEnumeration").Connection_Threshold,
                settings.GetValue<ServiceEnumerationConfig>("ServiceEnumeration").Min_Bytes_Transferred,
                httpLogs);

            await Task.WhenAll(portScansTask, versionScansTask, hostDiscoveryScansTask, protocolSpecificScansTask,
                               serviceEnumerationTask);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["PortScans"] = await portScansTask,
                ["VersionScans"] = await versionScansTask,
                ["HostDiscoveryScans"] = await hostDiscoveryScansTask,
                ["ProtocolSpecificScans"] = await protocolSpecificScansTask,
                ["ServiceEnumeration"] = await serviceEnumerationTask,
            };
        }

        public static async Task<Dictionary<string, ConnectionGroup>> DetectPortScansAsync(
            Dictionary<string, ConnectionGroup> input,
            int connThreshold,
            int portThreshold,
            List<SSHConnection> sshLogs,
            List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    if (kvp.Value.dest_ports.Count >= portThreshold)
                    {
                        var rejected = kvp.Value.connections.Where(c => c.conn_state == "S0" || c.conn_state == "REJ" || c.conn_state == "RSTOS0").ToList();
                        var s0 = rejected.Count(c => c.conn_state == "S0");
                        var rej = rejected.Count(c => c.conn_state == "REJ");
                        var rstos0 = rejected.Count(c => c.conn_state == "RSTOS0");

                        // Count failed SSH and SSL attempts for existing connections
                        var sshAttempts = kvp.Value.connections.Count(c => sshLogs.Any(s => s.uid == c.uid && s.auth_attempts > 0));
                        var sslAttempts = kvp.Value.connections.Count(c => sslLogs.Any(s => s.uid == c.uid && !s.established));

                        if (rejected.Count >= connThreshold)
                        {
                            var cG = kvp.Value.Copy();
                            cG.classification = "Port Scan";
                            cG.reason = $"More than {connThreshold} (total: {rejected.Count}) bad connections to more than {portThreshold} different ports States\n";
                            cG.reason += $"S0 (no answer) {s0}\n";
                            cG.reason += $"REJ (rejected) {rej}\n";
                            cG.reason += $"RSTOS0 (syn followed by reset) {rstos0}\n";
                            cG.reason += $"Failed SSH attempts: {sshAttempts}\n";
                            cG.reason += $"Failed SSL attempts: {sslAttempts}";

                            output[kvp.Key] = cG;
                        }
                    }
                }

                return output;
            });
        }

        public static async Task<Dictionary<string, ConnectionGroup>> DetectVersionScansAsync(
            Dictionary<string, ConnectionGroup> input,
            int[] commonPorts,
            int thresholdPortNumber,
            int thresholdConnNumber,
            int maximumBytes,
            List<SSHConnection> sshLogs,
            List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    var commonPortConnections = kvp.Value.connections
                        .Where(c => commonPorts.Contains(c.id_resp_p) &&
                                    (c.orig_bytes + c.resp_bytes) <= maximumBytes)
                        .ToList();

                    // Enhance connection information with SSH and SSL data
                    var enhancedConnections = commonPortConnections.Select(c => new
                    {
                        Connection = c,
                        SSHInfo = sshLogs.FirstOrDefault(s => s.uid == c.uid),
                        SSLInfo = sslLogs.FirstOrDefault(s => s.uid == c.uid)
                    });

                    var portCounts = enhancedConnections
                        .GroupBy(c => c.Connection.id_resp_p)
                        .Select(g => new { Port = g.Key, Count = g.Count() })
                        .Where(pc => pc.Count >= thresholdConnNumber)
                        .ToList();

                    if (portCounts.Count >= thresholdPortNumber)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Version Scan";
                        cG.reason = $"Multiple short connections to common ports with minimal data transfer:\n";
                        cG.reason += $"\tSaw: {portCounts.Count} ports with >= {thresholdConnNumber} connections each " +
                                     $"(threshold: {thresholdPortNumber} ports, <= {maximumBytes} Bytes per connection)";
                        cG.reason += $"\nPorts: {string.Join(", ", portCounts.Select(pc => $"{pc.Port} ({pc.Count} conns)"))}";
                        cG.reason += $"\nIncludes {enhancedConnections.Count(c => c.SSHInfo != null)} SSH and {enhancedConnections.Count(c => c.SSLInfo != null)} SSL connections";

                        output[kvp.Key] = cG;
                    }
                }

                return output;
            });
        }

        public static async Task<Dictionary<string, ConnectionGroup>> DetectHostDiscoveryScansAsync(
            Dictionary<string, ConnectionGroup> input,
            int threshold,
            List<DNSConnection> dnsLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    var uniqueDestIPs = kvp.Value.connections
                        .Select(c => c.id_resp_h)
                        .Distinct()
                        .Count();

                    // Count unique DNS queries for existing connections
                    var uniqueDNSQueries = kvp.Value.connections
                        .SelectMany(c => dnsLogs.Where(d => d.uid == c.uid).Select(d => d.query))
                        .Distinct()
                        .Count();

                    if (uniqueDestIPs >= threshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Host Discovery Scan";
                        cG.reason = $"Connections to multiple destination IPs and DNS queries:\n";
                        cG.reason += $"\tUnique Destination IPs: {uniqueDestIPs}\n";
                        cG.reason += $"\tUnique DNS Queries: {uniqueDNSQueries}\n";

                        output[kvp.Key] = cG;
                    }
                }

                return output;
            });
        }

        public static async Task<Dictionary<string, ConnectionGroup>> DetectProtocolSpecificScansAsync(
            Dictionary<string, ConnectionGroup> input,
            int threshold,
            List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    var synScans = kvp.Value.connections.Count(c => c.history == "S");

                    // Count SSL handshake attempts for existing connections
                    var sslHandshakes = kvp.Value.connections.Count(c => sslLogs.Any(s => s.uid == c.uid && !s.established));

                    if (synScans >= threshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Protocol-Specific Scan";
                        cG.reason = $"Multiple protocol-specific connection attempts:\n";
                        cG.reason += $"\tSYN-only connections: {synScans}\n";
                        cG.reason += $"\tFailed SSL handshakes: {sslHandshakes}\n";

                        output[kvp.Key] = cG;
                    }
                }

                return output;
            });
        }

        public static async Task<Dictionary<string, ConnectionGroup>> DetectServiceEnumerationAsync(
            Dictionary<string, ConnectionGroup> input,
            int[] commonPorts,
            int thresholdPortNumber,
            int thresholdConnNumber,
            int minimumBytes,
            List<HTTPConnection> httpLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();

                foreach (var kvp in input)
                {
                    var serviceConnections = kvp.Value.connections
                        .Where(c => commonPorts.Contains(c.id_resp_p) &&
                                    (c.orig_bytes + c.resp_bytes) >= minimumBytes)
                        .ToList();

                    // Enhance connection information with HTTP data
                    var enhancedConnections = serviceConnections.Select(c => new
                    {
                        Connection = c,
                        HTTPInfo = httpLogs.FirstOrDefault(h => h.uid == c.uid)
                    });

                    var portCounts = enhancedConnections
                        .GroupBy(c => c.Connection.id_resp_p)
                        .Select(g => new { Port = g.Key, Count = g.Count() })
                        .Where(pc => pc.Count >= thresholdConnNumber)
                        .ToList();

                    if (portCounts.Count >= thresholdPortNumber)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Service Enumeration";
                        cG.reason = $"Multiple connections to common ports with data transfer:\n";
                        cG.reason += $"\tSaw: {portCounts.Count} ports with >= {thresholdConnNumber} connections each " +
                                     $"(threshold: {thresholdPortNumber} ports, {minimumBytes} Bytes per connection)";
                        cG.reason += $"\nPorts: {string.Join(", ", portCounts.Select(pc => $"{pc.Port} ({pc.Count} conns)"))}";
                        cG.reason += $"\nIncludes {enhancedConnections.Count(c => c.HTTPInfo != null)} HTTP connections";

                        output[kvp.Key] = cG;
                    }
                }

                return output;
            });
        }
    }
}