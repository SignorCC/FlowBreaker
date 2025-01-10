using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ScottPlot;

namespace FlowBreaker
{
    static public class Analyzer
    {
        public static void PerformBasicAnalysis(List<Connection> connections)
        {
            ScottPlot.Plot uniqueIPsPlot = new();

            int uniqueOriginIPs = connections.Select(c => c.id_orig_h).Distinct().Count();
            int uniqueDestinationIPs = connections.Select(c => c.id_resp_h).Distinct().Count();

            uniqueIPsPlot.Add.Bar(position: 1, value: uniqueOriginIPs);
            uniqueIPsPlot.Add.Bar(position: 2, value: uniqueDestinationIPs);


            Tick[] ticks =
            {
                new(1, "Origin IPs"),
                new(2, "Destination IPs")
            };


            uniqueIPsPlot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericManual(ticks);

            uniqueIPsPlot.Axes.Bottom.MajorTickStyle.Length = 0;
            uniqueIPsPlot.Axes.Margins(bottom: 0);
            uniqueIPsPlot.Title("Unique IPs");

            uniqueIPsPlot.SavePng("unique_ips.png", 400, 400);


            ScottPlot.Plot topIPsPlot = new();

            var topOriginIPs = connections
                .GroupBy(c => c.id_orig_h)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToList();

            for (int i = 0; i < topOriginIPs.Count; i++)
            {
                topIPsPlot.Add.Bar(position: i + 1, value: topOriginIPs[i].Count());
            }

            ticks = topOriginIPs
                .Select((g, i) => new Tick(i + 1, g.Key))
                .ToArray();

            topIPsPlot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericManual(ticks);
            topIPsPlot.Axes.Bottom.MajorTickStyle.Length = 0;
            topIPsPlot.Axes.Margins(bottom: 0);
            topIPsPlot.Title("Top 10 Most Active Origin IPs");
            topIPsPlot.XLabel("IP Address");
            topIPsPlot.YLabel("Connection Count");

            topIPsPlot.SavePng("top_10_active_ips.png", 1000, 400);



            Plot protocolPlot = new();

            var protocolDistribution = connections
                .GroupBy(c => c.proto)
                .OrderByDescending(g => g.Count())
                .ToList();

            List<PieSlice> slices = new();
            double total = connections.Count;
            var rainbowColors = Colors.Rainbow(protocolDistribution.Count).ToArray(); // Generate different colors

            for (int i = 0; i < protocolDistribution.Count; i++)
            {
                var group = protocolDistribution[i];
                double percentage = group.Count() / total * 100;

                slices.Add(new PieSlice
                {
                    Value = group.Count(),
                    FillColor = rainbowColors[i],
                    Label = $"{percentage:F1}%",
                    LegendText = $"{group.Key}: {group.Count()} ({percentage:F1}%)"
                });
            }

            var pie = protocolPlot.Add.Pie(slices);
            pie.ExplodeFraction = 0.1;
            pie.SliceLabelDistance = 0.6;

            // Customize slice labels
            foreach (var slice in pie.Slices)
            {
                slice.LabelFontSize = 12;
                slice.LabelFontColor = Colors.Black;
                slice.LabelBold = true;
            }

            protocolPlot.ShowLegend(Alignment.UpperRight);

            // Hide unnecessary plot components
            protocolPlot.Axes.Frameless();
            protocolPlot.HideGrid();

            protocolPlot.Title("Connection Protocol Distribution");
            protocolPlot.SavePng("protocol_distribution.png", 600, 400);

            GetMostActiveDestinations(connections);
            //DetectPortScanning(connections, 10);
            DetectPotentialC2(connections, 10);
            DetectPotentialExfiltration(connections, 2.8);
            DetectPotentialDDoS(connections, 10);
            DetectUnusualDataTransfer(connections, 50000);

        }

        public static void GetMostActiveDestinations(List<Connection> connections)
        {
            ScottPlot.Plot topIPsPlot = new();

            var topDestIPs = connections
                .GroupBy(c => c.id_resp_h)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToList();

            for (int i = 0; i < topDestIPs.Count; i++)
            {
                topIPsPlot.Add.Bar(position: i + 1, value: topDestIPs[i].Count());
            }

            Tick[] ticks = topDestIPs
                .Select((g, i) => new Tick(i + 1, g.Key))
                .ToArray();

            topIPsPlot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericManual(ticks);
            topIPsPlot.Axes.Bottom.MajorTickStyle.Length = 0;
            topIPsPlot.Axes.Margins(bottom: 0);
            topIPsPlot.Title("Top 10 Most Active Destination IPs");
            topIPsPlot.XLabel("IP Address");
            topIPsPlot.YLabel("Connection Count");

            topIPsPlot.SavePng("top_10_active_dest_ips.png", 1000, 400);
        }

        public static void DetectPortScanning(List<Connection> connections, int threshold)
        {
            Utility.Log("Loaded Enhanced Port Scanning Detection with extended state analysis", Utility.Level.Info);

            // S0 no reply,
            // REJ - RES response,
            // RSTOS0 - SYN+RST,
            // OTH - open connection (midway traffic)
            var scanStates = new[] { "S0", "REJ", "RSTOS0", "OTH" };

            var scans = connections
                .GroupBy(c => c.id_resp_h) // Group by target IPs
                .Select(g => new
                {
                    TargetIP = g.Key, 
                    Scanners = g.GroupBy(c => c.id_orig_h) // Group by source IPs
                        .Select(sg => new
                        {
                            SourceIP = sg.Key,
                            ScanConnections = sg.Where(c => scanStates.Contains(c.conn_state)).ToList(), // Filter for TCP connection states
                            ScannedPorts = sg.Where(c => scanStates.Contains(c.conn_state))
                                             .Select(c => c.id_resp_p).Distinct().OrderBy(p => p).ToList(), // Get unique scanned ports
                            StateCounts = scanStates.ToDictionary(
                                state => state,
                                state => sg.Count(c => c.conn_state == state) // Count the number of connections for each TCP state (helps in classification)
                            )
                        })
                        .Where(s => s.ScannedPorts.Count > threshold)
                        .ToList()
                })
                .Where(s => s.Scanners.Any())
                .ToList();

            foreach (var scan in scans)
            {
                Console.WriteLine($"Potential port scan detected on target: {scan.TargetIP}");
                Console.WriteLine($"Number of scanning IPs: {scan.Scanners.Count}");

                foreach (var scanner in scan.Scanners)
                {
                    Console.WriteLine($"  Scanner IP: {scanner.SourceIP}");
                    Console.WriteLine($"  Unique ports scanned: {scanner.ScannedPorts.Count}");

                    foreach (var state in scanStates)
                        Console.WriteLine($"  {state} count: {scanner.StateCounts[state]}");
                    
                    Console.WriteLine($"  Total scan connections: {scanner.ScanConnections.Count}");
                    Console.WriteLine("  Scan connection details:");

                    foreach (var conn in scanner.ScanConnections)
                        Console.WriteLine($"    {conn}");

                    Console.WriteLine();
                }

                Console.WriteLine(new string('-', 80));
            }

            // Summary
            var totalScans = scans.Sum(s => s.Scanners.Count);
            var uniqueTargets = scans.Count;
            var uniqueScanners = scans.SelectMany(s => s.Scanners).Select(s => s.SourceIP).Distinct().Count();
            var stateTotals = scanStates.ToDictionary(
                state => state,
                state => scans.Sum(s => s.Scanners.Sum(sc => sc.StateCounts[state]))
            );

            Console.WriteLine("Port Scanning Summary:");
            Console.WriteLine($"Total potential port scans detected: {totalScans}");
            Console.WriteLine($"Unique target IPs: {uniqueTargets}");
            Console.WriteLine($"Unique scanner IPs: {uniqueScanners}");
            foreach (var state in scanStates)
            {
                Console.WriteLine($"Total {state} connections: {stateTotals[state]}");
            }
        }

        public static void DetectPotentialC2(List<Connection> connections, int frequencyThreshold)
        {
            var potentialC2 = connections
                .GroupBy(c => new { c.id_orig_h, c.id_resp_h })
                .Where(g => g.Count() > frequencyThreshold && g.Average(c => c.duration) < 1)
                .Select(g => new {
                    SourceIP = g.Key.id_orig_h,
                    DestinationIP = g.Key.id_resp_h,
                    ConnectionCount = g.Count(),
                    AverageDuration = g.Average(c => c.duration)
                });

            foreach (var c2 in potentialC2)
                Console.WriteLine($"Potential C2: {c2.SourceIP} -> {c2.DestinationIP}, {c2.ConnectionCount} connections, avg duration {c2.AverageDuration:F2}s");
        }

        public static void DetectPotentialExfiltration(List<Connection> connections, double ratio)
        {
            var potentialExfiltration = connections
                .Where(c => c.orig_bytes > 0 && c.resp_bytes > 0 && (double)c.orig_bytes / c.resp_bytes > ratio)
                .Select(c => new {
                    SourceIP = c.id_orig_h,
                    DestinationIP = c.id_resp_h,
                    Ratio = (double)c.orig_bytes / c.resp_bytes
                });

            foreach (var ex in potentialExfiltration)
                Console.WriteLine($"Potential exfiltration: {ex.SourceIP} -> {ex.DestinationIP}, ratio: {ex.Ratio:F2}");
        }

        public static void DetectPotentialDDoS(List<Connection> connections, int threshold)
        {
            var potentialDDoS = connections
                .GroupBy(c => c.id_resp_h)
                .Where(g => g.Select(c => c.id_orig_h).Distinct().Count() > threshold)
                .Select(g => new {
                    TargetIP = g.Key,
                    UniqueSourceIPs = g.Select(c => c.id_orig_h).Distinct().Count(),
                    TotalConnections = g.Count()
                });

            foreach (var ddos in potentialDDoS)
                Console.WriteLine($"Potential DDoS: {ddos.TargetIP} received {ddos.TotalConnections} connections from {ddos.UniqueSourceIPs} unique IPs");
        }

        public static void DetectUnusualDataTransfer(List<Connection> connections, long threshold)
        {
            var largeTransfers = connections
                .Where(c => c.orig_bytes + c.resp_bytes > threshold)
                .Select(c => new {
                    SourceIP = c.id_orig_h,
                    DestinationIP = c.id_resp_h,
                    TotalBytes = c.orig_bytes + c.resp_bytes
                });

            foreach (var transfer in largeTransfers)
                Console.WriteLine($"Large data transfer: {transfer.SourceIP} -> {transfer.DestinationIP}, {transfer.TotalBytes} bytes");
        }

        public static Dictionary<string, ConnectionGroup> DetectPortScanning(Dictionary<string, ConnectionGroup> input, int threshold)
        {
            Dictionary<string, ConnectionGroup> output = new();

            foreach(var kvp in input)
                if(kvp.Value.highInPort)
                    if(kvp.Value.dest_ports.Count >= threshold)
                    {
                        var rejected = kvp.Value.connections.Where(c => c.conn_state == "S0" || c.conn_state == "REJ" || c.conn_state == "RSTOS0" ).ToList();

                        if (rejected.Count >= threshold)
                        {
                            var cG = kvp.Value;

                            cG.classification = "Portscan or SynFlood";
                            cG.reason = $"Unanswered Connections to Ports:\n";

                            foreach (var port in kvp.Value.dest_ports.OrderBy(p => p.Key))
                                cG.reason += $"\tPort: {port.Key}: {port.Value} connection(s)\n";

                            output.Add(kvp.Key, cG);

                        }
                    } 

            return output;
        }

        public static Dictionary<string, ConnectionGroup> DetectBruteForce(Dictionary<string, ConnectionGroup> input, int threshold)
        {
            // Find connections where connections per port > threshold
            Dictionary<string, ConnectionGroup> output = new();

            foreach(var kvp in input)
            {
                Dictionary<int, long> portCounts = new();

                kvp.Value.dest_ports.Where(p => p.Value >= threshold).ToList().ForEach(p => portCounts.Add(p.Key, p.Value));

                if (portCounts.Count > 0)
                {
                    var cG = kvp.Value;

                    cG.classification = "Brute Force";
                    cG.reason = $"High Number of Connections to port(s):\n";

                    foreach(var port in portCounts)
                        cG.reason += $"\tPort: {port.Key}: ({port.Value})\n";

                    output.Add(kvp.Key, cG);
                }
                    
            }

            return output;
        }

        public static Dictionary<string, ConnectionGroup> DetectTCPStarvationAttack(Dictionary<string, ConnectionGroup> input, int threshold)
        {
            // Similar to DetectPortScanning, but connections actually receive SYN-ACK
            Dictionary<string, ConnectionGroup> output = new();

            foreach (var kvp in input)
            {
                if (kvp.Value.connections.Count >= threshold)
                    if (kvp.Value.dest_ports.Count >= threshold)
                    {
                        var rejected = kvp.Value.connections.Where(c => c.conn_state == "S1").ToList();

                        if (rejected.Count >= threshold)
                        {
                            var cG = kvp.Value;

                            cG.classification = "TCP Starvation Attack";
                            cG.reason = $"High Number of Connections in S1 or OTH state to Ports:\n";

                            foreach (var port in kvp.Value.dest_ports.OrderBy(p => p.Key))
                                cG.reason += $"\tPort: {port.Key}: {port.Value} connection(s)\n";

                            output.Add(kvp.Key, cG);

                        }
                    }

            }

            return output;
        }




    }
}
