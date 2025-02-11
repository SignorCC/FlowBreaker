using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;

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
            // Pre-process logs for faster lookups
            var sshLogDict = sshLogs.GroupBy(s => s.uid).ToDictionary(g => g.Key, g => g.First());
            var sslLogDict = sslLogs.GroupBy(s => s.uid).ToDictionary(g => g.Key, g => g.First());
            var httpLogDict = httpLogs.GroupBy(h => h.uid).ToDictionary(g => g.Key, g => g.First());

            var commonPortsAttack = settings.GetValue<CommonPortsAttackConfig>("CommonPortsAttack");
            var passwordSprayingConfig = settings.GetValue<PasswordSprayingConfig>("PasswordSpraying");
            var sshBruteForceConfig = settings.GetValue<SSHBruteForceConfig>("SSHBruteForce");
            var sslBruteForceConfig = settings.GetValue<SSLBruteForceConfig>("SSLBruteForce");
            var httpBruteForceConfig = settings.GetValue<HTTPBruteForceConfig>("HTTPBruteForce");

            var tasks = new[]
            {
                DetectCommonPortAttacksAsync(tcpDestination, commonPortsAttack, sshLogDict, sslLogDict),
                DetectPasswordSprayingAsync(tcpSource, passwordSprayingConfig, sshLogDict, sslLogDict, httpLogDict),
                DetectSSHBruteForceAsync(tcpSource, sshBruteForceConfig, sshLogDict),
                DetectSSLBruteForceAsync(tcpSource, sslBruteForceConfig, sslLogDict),
                DetectHTTPBruteForceAsync(tcpSource, httpBruteForceConfig, httpLogDict)
            };

            await Task.WhenAll(tasks);

            return new Dictionary<string, Dictionary<string, ConnectionGroup>>
            {
                ["CommonPortAttacks"] = await tasks[0],
                ["PasswordSpraying"] = await tasks[1],
                ["SSHBruteForce"] = await tasks[2],
                ["SSLBruteForce"] = await tasks[3],
                ["HTTPBruteForce"] = await tasks[4]
            };
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectCommonPortAttacksAsync(
            Dictionary<string, ConnectionGroup> input, CommonPortsAttackConfig config,
            Dictionary<string, SSHConnection> sshLogs, Dictionary<string, SSLConnection> sslLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var suspiciousConnections = config.CommonPorts
                        .Select(port => new
                        {
                            Port = port,
                            Count = kvp.Value.connections.Count(c => c.id_resp_p == port),
                            SSHAttempts = kvp.Value.connections.Count(c => c.id_resp_p == port && sshLogs.ContainsKey(c.uid)),
                            SSLAttempts = kvp.Value.connections.Count(c => c.id_resp_p == port && sslLogs.TryGetValue(c.uid, out var ssl) && !ssl.established)
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
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectPasswordSprayingAsync(
            Dictionary<string, ConnectionGroup> input, PasswordSprayingConfig config,
            Dictionary<string, SSHConnection> sshLogs, Dictionary<string, SSLConnection> sslLogs, Dictionary<string, HTTPConnection> httpLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var relevantConnections = kvp.Value.connections
                        .Where(c => config.CommonPorts.Contains(c.id_resp_p))
                        .ToList();

                    var uniqueDestinations = relevantConnections
                        .Select(c => c.id_resp_h)
                        .Distinct()
                        .Count();

                    var sshAttempts = relevantConnections.Count(c => sshLogs.ContainsKey(c.uid));
                    var sslAttempts = relevantConnections.Count(c => sslLogs.TryGetValue(c.uid, out var ssl) && !ssl.established);
                    var httpAttempts = relevantConnections.Count(c => httpLogs.ContainsKey(c.uid));

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
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectSSHBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, SSHBruteForceConfig config, Dictionary<string, SSHConnection> sshLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var sshConnections = kvp.Value.connections
                        .Where(c => c.service == "ssh")
                        .ToList();

                    var sshAttempts = sshConnections.Count(c => sshLogs.ContainsKey(c.uid));

                    if (sshAttempts >= config.MinConnections)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSH Brute Force Attack";
                        cG.reason = $"High number of SSH connection attempts: {sshAttempts}\n" +
                                    $"Total SSH connections: {sshConnections.Count}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectSSLBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, SSLBruteForceConfig config, Dictionary<string, SSLConnection> sslLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var sslConnections = kvp.Value.connections
                        .Where(c => c.service == "tls")
                        .ToList();

                    var failedSSLHandshakes = sslConnections.Count(c => sslLogs.TryGetValue(c.uid, out var ssl) && !ssl.established);

                    if (failedSSLHandshakes >= config.MinConnections)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "SSL/TLS Brute Force Attack";
                        cG.reason = $"High number of failed SSL/TLS handshakes: {failedSSLHandshakes}\n" +
                                    $"Total SSL/TLS connections: {sslConnections.Count}";
                        output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }

        private static Task<Dictionary<string, ConnectionGroup>> DetectHTTPBruteForceAsync(
            Dictionary<string, ConnectionGroup> input, HTTPBruteForceConfig config, Dictionary<string, HTTPConnection> httpLogs)
        {
            return Task.Run(() =>
            {
                var output = new ConcurrentDictionary<string, ConnectionGroup>();
                Parallel.ForEach(input, kvp =>
                {
                    var httpConnections = kvp.Value.connections
                        .Where(c => c.service == "http")
                        .ToList();

                    var httpAttempts = httpConnections.Count(c => httpLogs.ContainsKey(c.uid));

                    if (httpAttempts >= config.MinConnections)
                    {
                        var cG = kvp.Value.Copy();
                        cG.classification = "HTTP Brute Force Attack";
                        cG.reason = $"High number of HTTP requests: {httpAttempts}\n" +
                                    $"Total HTTP connections: {httpConnections.Count}";
                        //output[kvp.Key] = cG;
                    }
                });
                return output.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            });
        }
    }
}