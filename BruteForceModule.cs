using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FlowBreaker
{
    public static class BruteForceModule
    {
        public static async Task<Dictionary<string, Dictionary<string, ConnectionGroup>>> ExecuteModuleAsync(
            Dictionary<string, ConnectionGroup> tcpDestination,
            Dictionary<string, ConnectionGroup> tcpSource,
            Configuration settings,
            List<SSHConnection> sshLogs,
            List<DNSConnection> dnsLogs,
            List<SSLConnection> sslLogs,
            List<HTTPConnection> httpLogs)
        {
            var bruteForceConfig = settings.GetValue<BruteForceConfig>("BruteForce");

            var commonPortAttacksTask = DetectCommonPortAttacksAsync(tcpDestination, bruteForceConfig, sshLogs, sslLogs);
            var passwordSprayingTask = DetectPasswordSprayingAsync(tcpSource, bruteForceConfig, sshLogs, sslLogs, httpLogs);
            var sshBruteForceTask = DetectSSHBruteForceAsync(tcpSource, bruteForceConfig, sshLogs);
            var sslBruteForceTask = DetectSSLBruteForceAsync(tcpSource, bruteForceConfig, sslLogs);
            var httpBruteForceTask = DetectHTTPBruteForceAsync(tcpSource, bruteForceConfig, httpLogs);

            await Task.WhenAll(commonPortAttacksTask, passwordSprayingTask, sshBruteForceTask, sslBruteForceTask, httpBruteForceTask);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["CommonPortAttacks"] = await commonPortAttacksTask,
                ["PasswordSpraying"] = await passwordSprayingTask,
                ["SSHBruteForce"] = await sshBruteForceTask,
                ["SSLBruteForce"] = await sslBruteForceTask,
                ["HTTPBruteForce"] = await httpBruteForceTask
            };
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectCommonPortAttacksAsync(
            Dictionary<string, ConnectionGroup> input, BruteForceConfig config,
            List<SSHConnection> sshLogs, List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var suspiciousConnections = config.CommonPorts
                        .Select(port => new
                        {
                            Port = port,
                            Count = kvp.Value.connections.Count(c => c.id_resp_p == port),
                            SSHAttempts = sshLogs.Count(s => s.id_resp_p == port && kvp.Value.connections.Any(c => c.uid == s.uid)),
                            SSLAttempts = sslLogs.Count(s => s.id_resp_p == port && kvp.Value.connections.Any(c => c.uid == s.uid) && !s.established)
                        })
                        .Where(x => x.Count >= config.MinConnectionsPerPort)
                        .ToList();

                    if (suspiciousConnections.Count > 0)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Common Port Brute Force Attack";
                        cG.reason = $"High number of connection attempts: " +
                            string.Join(", ", suspiciousConnections.Select(x =>
                                $"Port {x.Port}: {x.Count} (SSH: {x.SSHAttempts}, SSL: {x.SSLAttempts})"));
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectPasswordSprayingAsync(
            Dictionary<string, ConnectionGroup> input, BruteForceConfig config,
            List<SSHConnection> sshLogs, List<SSLConnection> sslLogs, List<HTTPConnection> httpLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var relevantConnections = kvp.Value.connections
                        .Where(c => config.CommonPorts.Contains(c.id_resp_p))
                        .ToList();

                    var uniqueDestinations = relevantConnections
                        .Select(c => c.id_resp_h)
                        .Distinct()
                        .Count();

                    var sshAttempts = sshLogs.Count(s => relevantConnections.Any(c => c.uid == s.uid));
                    var sslAttempts = sslLogs.Count(s => relevantConnections.Any(c => c.uid == s.uid) && !s.established);
                    var httpAttempts = httpLogs.Count(h => relevantConnections.Any(c => c.uid == h.uid));

                    if (uniqueDestinations >= config.PasswordSprayingThreshold)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "Password Spraying";
                        cG.reason = $"Attempts to many unique destinations: {uniqueDestinations}\n" +
                            $"SSH attempts: {sshAttempts}\n" +
                            $"SSL attempts: {sslAttempts}\n" +
                            $"HTTP attempts: {httpAttempts}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectSSHBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, BruteForceConfig config, List<SSHConnection> sshLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var sshConnections = kvp.Value.connections
                        .Where(c => c.id_resp_p == 22 || c.service == "ssh")
                        .ToList();

                    var sshAttempts = sshLogs.Count(s => sshConnections.Any(c => c.uid == s.uid));

                    if (sshAttempts >= config.MinConnectionsPerPort)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSH Brute Force Attack";
                        cG.reason = $"High number of SSH connection attempts: {sshAttempts}\n" +
                                    $"Total SSH connections: {sshConnections.Count}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectSSLBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, BruteForceConfig config, List<SSLConnection> sslLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var sslConnections = kvp.Value.connections
                        .Where(c => c.id_resp_p == 443 || c.service == "tls")
                        .ToList();

                    var failedSSLHandshakes = sslLogs.Count(s => sslConnections.Any(c => c.uid == s.uid) && !s.established);

                    if (failedSSLHandshakes >= config.MinConnectionsPerPort)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSL/TLS Brute Force Attack";
                        cG.reason = $"High number of failed SSL/TLS handshakes: {failedSSLHandshakes}\n" +
                                    $"Total SSL/TLS connections: {sslConnections.Count}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }

        private static async Task<Dictionary<string, ConnectionGroup>> DetectHTTPBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, BruteForceConfig config, List<HTTPConnection> httpLogs)
        {
            return await Task.Run(() =>
            {
                var output = new Dictionary<string, ConnectionGroup>();
                foreach (var kvp in input)
                {
                    var httpConnections = kvp.Value.connections
                        .Where(c => c.id_resp_p == 80 || c.id_resp_p == 443 || c.service == "http")
                        .ToList();

                    var httpAttempts = httpLogs.Count(h => httpConnections.Any(c => c.uid == h.uid));

                    if (httpAttempts >= config.MinConnectionsPerPort)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "HTTP Brute Force Attack";
                        cG.reason = $"High number of HTTP requests: {httpAttempts}\n" +
                                    $"Total HTTP connections: {httpConnections.Count}";
                        output[kvp.Key] = cG;
                    }
                }
                return output;
            });
        }
    }
}