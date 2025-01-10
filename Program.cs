using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace FlowBreaker
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length > 0)
                await RunWithArguments(args);
            
            else
                await RunWithoutArguments();
            
        }

        static async Task RunWithArguments(string[] args)
        {
            string inputPath = null;
            string outputPath = null;
            string configFilePath = null;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-i":
                        if (i + 1 < args.Length) inputPath = args[++i];
                        break;
                    case "-o":
                        if (i + 1 < args.Length) outputPath = args[++i];
                        break;
                    case "-c":
                        if (i + 1 < args.Length) configFilePath = args[++i];
                        break;
                }
            }

            if (string.IsNullOrEmpty(inputPath) || string.IsNullOrEmpty(outputPath) || string.IsNullOrEmpty(configFilePath))
            {
                Console.WriteLine("Error: All arguments (-i, -o, -c) are required.");
                Console.WriteLine("Usage: FlowBreaker.exe -i <inputPath> -o <outputPath> -c <configFilePath>");
                return;
            }

            try
            {
                Configuration config = new Configuration(configFilePath);
                await RunModules(inputPath, outputPath, config);
            }

            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static async Task RunWithoutArguments()
        {
            string rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\test_20241110_152738\\useful";
            rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\amp.dns.RRSIG.fragmented_20241112_215014";
            rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\CIC-DDoS-2019-SynFlood_20241113_173032";
            //rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\CIC-DDoS-2019-Benign_20241113_180110";
            //rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\pcaps_PracticalPacketAnalysis_ppa-capture-files\\portscan_20241116_231416";
            //rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\amp.TCP.syn.optionallyACK.optionallysamePort.pcapng_20241212_205015"; // TCP starvation attack
            rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\nmap.scanme.nmap.org.pcapng_20241212_224051"; // Nmap scan unstealthy
            //rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\Results\\nmap.stealth.scanme.nmap.org-24_incomplete.pcapng_20241212_225600"; // Nmap scan stealthy
            rootDir = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Pcaps+Auswertungen\\TII-SSRC-23_Dataset\\bruteforce_ssh_20250110_010827"; // SSH brute force


            string outputPath = "C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps\\Program_Output";
            string configPath = Path.Combine("C:\\Data\\Seafile\\StandardLib\\Master\\Masterarbeit\\PacketCaps", "config.toml");

            Configuration config = new Configuration(configPath);
            await RunModules(rootDir, outputPath, config);
        }

        static async Task RunModules(string inputPath, string outputPath, Configuration config)
        {
            List<Connection> conn;

            // These default to empty if files are not present
            List<DNSConnection> dns = await LogHandler.ParseDNSAsync(Path.Combine(inputPath, "dns.log"));
            List<SSLConnection> ssl = await LogHandler.ParseSSLAsync(Path.Combine(inputPath, "ssl.log"));
            List<SSHConnection> ssh = await LogHandler.ParseSSHAsync(Path.Combine(inputPath, "ssh.log"));
            List<HTTPConnection> http = await LogHandler.ParseHTTPAsync(Path.Combine(inputPath, "http.log"));

            List<string> loadedModules = config.GetValue<List<string>>("Enabled_Modules");

            // Log to Console
            Utility.Log("Starting loaded modules:", Utility.Level.Scheduling);
            foreach (var module in loadedModules)
                Utility.Log(module, Utility.Level.Indent1);

            try
            {
                conn = await LogHandler.ParseConnectionAsync(Path.Combine(inputPath, "conn.log"));

                var rC = ConnectionProcessor.SplitByProtocol(conn);
                rC.TryGetValue("TCP", out var TCP);
                rC.TryGetValue("UDP", out var UDP);
                rC.TryGetValue("ICMP", out var ICMP);

                var destinationGroupsTCP = new Dictionary<string, ConnectionGroup>();
                var sourceGroupsTCP = new Dictionary<string, ConnectionGroup>();
                var destinationGroupsUDP = new Dictionary<string, ConnectionGroup>();
                var sourceGroupsUDP = new Dictionary<string, ConnectionGroup>();
                var destinationGroupsICMP = new Dictionary<string, ConnectionGroup>();
                var sourceGroupsICMP = new Dictionary<string, ConnectionGroup>();

                var processedDestinationTCP = new Dictionary<string, ConnectionGroup>();
                var processedSourceTCP = new Dictionary<string, ConnectionGroup>();
                var processedDestinationUDP = new Dictionary<string, ConnectionGroup>();
                var processedSourceUDP = new Dictionary<string, ConnectionGroup>();
                var processedDestinationICMP = new Dictionary<string, ConnectionGroup>();
                var processedSourceICMP = new Dictionary<string, ConnectionGroup>();

                // Process TCP connections if present
                if (TCP != null && TCP.connections.Count > 0)
                {
                    destinationGroupsTCP = ConnectionProcessor.SplitByDestinationIP(TCP);
                    sourceGroupsTCP = ConnectionProcessor.SplitBySourceIP(TCP);
                    (processedSourceTCP, processedDestinationTCP) = ConnectionProcessor.SetFlags(sourceGroupsTCP, destinationGroupsTCP, config, "TCP");
                }

                // Process UDP connections if present
                if (UDP != null && UDP.connections.Count > 0)
                {
                    destinationGroupsUDP = ConnectionProcessor.SplitByDestinationIP(UDP);
                    sourceGroupsUDP = ConnectionProcessor.SplitBySourceIP(UDP);
                    (processedSourceUDP, processedDestinationUDP) = ConnectionProcessor.SetFlags(sourceGroupsUDP, destinationGroupsUDP, config, "UDP");
                }

                // Process ICMP connections if present
                if (ICMP != null && ICMP.connections.Count > 0)
                {
                    destinationGroupsICMP = ConnectionProcessor.SplitByDestinationIP(ICMP);
                    sourceGroupsICMP = ConnectionProcessor.SplitBySourceIP(ICMP);
                    (processedSourceICMP, processedDestinationICMP) = ConnectionProcessor.SetFlags(sourceGroupsICMP, destinationGroupsICMP, config, "ICMP");
                }

                // Create Results folder if not present
                Directory.CreateDirectory(Path.Combine(outputPath, "Results"));
                Directory.CreateDirectory(Path.Combine(outputPath, "Results", "RawConnections"));

                if (loadedModules.Contains("Scanning"))
                {
                    Directory.CreateDirectory(Path.Combine(outputPath, "Results", "ScanningModule"));

                    // Execute Scanning Module
                    Utility.Log("Executing Scanning Module...", Utility.Level.Task);
                    var ScanningModuleResults = await ScanningModule.ExecuteModuleAsync(processedDestinationTCP, processedSourceTCP, config, ssh, dns, ssl, http);
                    Utility.Log("Scanning Module finished.", Utility.Level.Result);

                    // Write results to file
                    Utility.Log("Writing results to disk...", Utility.Level.Task);
                    await WriteResultsAsync(ScanningModuleResults, Path.Combine(outputPath, "Results", "ScanningModule"));                    
                    Utility.Log("Results written to disk.", Utility.Level.Result);
                }

                if (loadedModules.Contains("BruteForce"))
                {
                    Directory.CreateDirectory(Path.Combine(outputPath, "Results", "BruteForceModule"));

                    // Execute BruteForce Module
                    Utility.Log("Executing BruteForce Module...", Utility.Level.Task);
                    var BruteForceModuleResults = await BruteForceModule.ExecuteModuleAsync(
                        processedDestinationTCP, processedSourceTCP, config, ssh, dns, ssl, http);
                    Utility.Log("BruteForce Module finished.", Utility.Level.Result);

                    // Write results to file
                    Utility.Log("Writing results to disk...", Utility.Level.Task);
                    await WriteResultsAsync(BruteForceModuleResults, Path.Combine(outputPath, "Results", "BruteForceModule"));
                    Utility.Log("Results written to disk.", Utility.Level.Result);
                }

                if (loadedModules.Contains("DDoS"))
                {
                    Directory.CreateDirectory(Path.Combine(outputPath, "Results", "DDoSModule"));

                    // Execute DDOS Module
                    Utility.Log("Executing DDOS Module...", Utility.Level.Task);
                    var DDOSModuleResults = await DDOSModule.ExecuteModuleAsync(
                        processedDestinationTCP, processedSourceTCP,
                        processedDestinationUDP, processedSourceUDP,
                        processedDestinationICMP, processedSourceICMP,
                        config, ssh, dns, ssl, http);
                    Utility.Log("DDOS Module finished.", Utility.Level.Result);

                    // Write results to file
                    Utility.Log("Writing results to disk...", Utility.Level.Task);
                    await WriteResultsAsync(DDOSModuleResults, Path.Combine(outputPath, "Results", "DDoSModule"));
                    Utility.Log("Results written to disk.", Utility.Level.Result);
                }

                // Finally write raw connections to disk
                Utility.Log("Writing results to disk...", Utility.Level.Task);
                Dictionary<string, Dictionary<string, ConnectionGroup>> processedTCPConnections = new Dictionary<string, Dictionary<string, ConnectionGroup>>()
                    {
                        { "Destination_TCP", processedDestinationTCP },
                        { "Source_TCP", processedSourceTCP }
                    };
                Dictionary<string, Dictionary<string, ConnectionGroup>> processedUDPConnections = new Dictionary<string, Dictionary<string, ConnectionGroup>>()
                    {
                        { "Destination_UDP", processedDestinationUDP },
                        { "Source_UDP", processedSourceUDP }
                    };
                Dictionary<string, Dictionary<string, ConnectionGroup>> processedICMPConnections = new Dictionary<string, Dictionary<string, ConnectionGroup>>()
                    {
                        { "Destination_ICMP", processedDestinationICMP },
                        { "Source_ICMP", processedSourceICMP }
                    };

                await WriteResultsAsync(processedTCPConnections, Path.Combine(outputPath, "Results", "RawConnections"));
                await WriteResultsAsync(processedUDPConnections, Path.Combine(outputPath, "Results", "RawConnections"));
                await WriteResultsAsync(processedICMPConnections, Path.Combine(outputPath, "Results", "RawConnections"));

                Utility.Log("Results written to disk.", Utility.Level.Result);

            }
            catch (Exception ex)
            {
                Utility.Log(ex.Message, Utility.Level.Error);
                Environment.Exit(-1);
            }

            Utility.Log("Finished.", Utility.Level.Scheduling);
        }

        public static async Task WriteResultsAsync(Dictionary<string, Dictionary<string, ConnectionGroup>> ModuleResults, string path)
        {
            var writeTasks = ModuleResults
                .Where(kvp => kvp.Value.Count > 0)
                .SelectMany(kvp =>
                {
                    string baseName = Path.Combine(path, kvp.Key);
                    return new[]
                    {
                    WriteLogFileAsync(baseName + ".log", Formatter.FormatConnections(kvp.Value)),
                    WriteCsvFileAsync(baseName + ".csv", Formatter.FormatConnectionsAsCsv(kvp.Value)),
                    WriteJsonFileAsync(baseName + ".json", Formatter.FormatConnectionsAsJson(kvp.Value))
                    };
                });

            await Task.WhenAll(writeTasks);
        }

        private static async Task WriteLogFileAsync(string filePath, string content)
        {
            await File.WriteAllTextAsync(filePath, content);
        }

        private static async Task WriteCsvFileAsync(string filePath, string content)
        {
            await File.WriteAllTextAsync(filePath, content);
        }

        private static async Task WriteJsonFileAsync(string filePath, string content)
        {
            await File.WriteAllTextAsync(filePath, content);
        }


    }
}
