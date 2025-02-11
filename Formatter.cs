using Newtonsoft.Json;
using System.Text;
using System.Threading.Tasks;

namespace FlowBreaker
{
    public static class Formatter
    {
        public static async Task FormatConnectionsAsync(Dictionary<string, ConnectionGroup> ips, string outputPath)
        {
            using var writer = new StreamWriter(outputPath, false, Encoding.UTF8, 65536);
            var sortedIPs = ips.OrderByDescending(kvp => kvp.Value.connections.Count);

            foreach (var kvp in sortedIPs)
            {
                string ip = kvp.Key;
                ConnectionGroup group = kvp.Value;
                bool isSourceIP = false;

                var sb = new StringBuilder(4096);

                sb.AppendLine($"IP: {ip}")
                  .AppendLine($"Total Connections: {group.connections.Count}")
                  .AppendLine($"Protocol: {group.proto}")
                  .AppendLine($"Service: {group.service}")
                  .AppendLine($"Classification: {group.classification}");

                if (group.classification != "UNDEF")
                    sb.AppendLine($"Reason:\n{group.reason}");

                sb.AppendLine("Connection Summary:");


                if (!(group.dest_ips.First().Key == ip && group.dest_ips.Count == 1))
                {
                    isSourceIP = true;
                    sb.AppendLine($"\tUnique Destination IPs: {group.dest_ips.Count}")
                      .AppendLine("\tDestination IPs:");

                    foreach (var destIP in group.dest_ips.OrderByDescending(x => x.Value))
                        sb.AppendLine($"\t\t{destIP.Key}: {destIP.Value} connections");
                }

                if (!(group.src_ips.First().Key == ip && group.src_ips.Count == 1))
                {
                    sb.AppendLine($"\tUnique Source IPs: {group.src_ips.Count}")
                      .AppendLine("\tSource IPs:");

                    foreach (var srcIP in group.src_ips.OrderByDescending(x => x.Value))
                        sb.AppendLine($"\t\t{srcIP.Key}: {srcIP.Value} connections");
                }

                sb.AppendLine($"\tUnique Destination Ports: {group.dest_ports.Count}")
                  .AppendLine("\t\tDestination Ports:");

                foreach (var destPort in group.dest_ports.OrderBy(x => x.Key))
                    sb.AppendLine($"\t\t\t{destPort.Key}: {destPort.Value} connections");

                sb.AppendLine($"\tUnique Source Ports: {group.src_ports.Count}")
                  .AppendLine("\t\tSource Ports:");

                foreach (var srcPort in group.src_ports.OrderBy(x => x.Key))
                    sb.AppendLine($"\t\t\t{srcPort.Key}: {srcPort.Value} connections");

                sb.AppendLine("Services:");
                foreach (var service in group.services.OrderByDescending(x => x.Value))
                    sb.AppendLine($"\t{service.Key}: {service.Value} connections");

                sb.AppendLine("Activity Flags:")
                  .AppendLine($"\tHigh Outgoing Port Activity: {group.highOutPort}")
                  .AppendLine($"\tHigh Incoming Port Activity: {group.highInPort}")
                  .AppendLine($"\tHigh Outgoing IP Activity: {group.highOutIP}")
                  .AppendLine($"\tHigh Incoming IP Activity: {group.highInIP}")
                  .AppendLine($"\tHigh Number of Outgoing Connections: {group.highOutConnIP}")
                  .AppendLine($"\tHigh Number of Incoming Connections: {group.highInConnIP}")
                  .AppendLine($"\tListener: {group.listener}")
                  .AppendLine($"\tSpeaker: {group.speaker}");

                sb.AppendLine("Flagging Scores (Current Value/Average Value):")
                  .AppendLine($"\tOutgoing Port Activity: {group.valHighOutPort}")
                  .AppendLine($"\tIncoming Port Activity: {group.valHighInPort}")
                  .AppendLine($"\tOutgoing IP Activity: {group.valHighOutIP}")
                  .AppendLine($"\tIncoming IP Activity: {group.valHighInIP}")
                  .AppendLine($"\tOutgoing Connections: {group.valHighOutConnIP}")
                  .AppendLine($"\tIncoming Connections: {group.valHighInConnIP}");

                // Calculate total Bytes transferred
                long totalBytes = 0;
                long ipBytes = 0;
                foreach (var conn in group.connections)
                {
                    totalBytes += conn.orig_bytes + conn.resp_bytes;
                    ipBytes += conn.orig_ip_bytes + conn.resp_ip_bytes;
                }

                sb.AppendLine("Average Values:")
                  .AppendLine($"\tConnections per Destination IP: {group.AverageConnectionsPerDestinationIP}")
                  .AppendLine($"\tConnections per Source IP: {group.AverageConnectionsPerSourceIP}")
                  .AppendLine($"\tConnections per Destination Port: {group.AverageConnectionsPerDestinationPort}")
                  .AppendLine($"\tConnections per Source Port: {group.AverageConnectionsPerSourcePort}")
                  .AppendLine($"\tConnections per Unique IP: {group.AverageConnectionsPerUniqueIP}");

                if (group.connections.Count != 0)
                {
                    sb.AppendLine($"\tBytes transferred per Connection: {(float)totalBytes / group.connections.Count}")
                     .AppendLine($"\tIP Bytes transferred per Connection: {(float)ipBytes / group.connections.Count}")
                     .AppendLine($"\tBytes transferred per Connection: {(float)totalBytes / group.connections.Count}")
                     .AppendLine($"\tIP Bytes transferred per Connection: {(float)ipBytes / group.connections.Count}");
                }

                sb.AppendLine(new string('-', 80));

                await writer.WriteAsync(sb);
            }
        }

        public static async Task FormatConnectionsAsCsvAsync(Dictionary<string, ConnectionGroup> ips, string outputPath)
        {
            using var writer = new StreamWriter(outputPath, false, Encoding.UTF8, 65536);
            await writer.WriteLineAsync("IP,TotalConnections,Protocol,Service,Classification,UniqueDestinationIPs,UniqueSourceIPs,UniqueDestinationPorts,UniqueSourcePorts,HighOutgoingPortActivity,HighIncomingPortActivity,HighOutgoingIPActivity,HighIncomingIPActivity,HighOutgoingConnections,HighIncomingConnections,Listener,Speaker,OutgoingPortActivityScore,IncomingPortActivityScore,OutgoingIPActivityScore,IncomingIPActivityScore,OutgoingConnectionsScore,IncomingConnectionsScore,AvgConnectionsPerDestIP,AvgConnectionsPerSourceIP,AvgConnectionsPerDestPort,AvgConnectionsPerSourcePort,AvgConnectionsPerUniqueIP");

            foreach (var kvp in ips.OrderByDescending(x => x.Value.connections.Count))
            {
                var group = kvp.Value;
                var line = $"{kvp.Key},{group.connections.Count},{group.proto},{group.service},{group.classification},{group.dest_ips.Count},{group.src_ips.Count},{group.dest_ports.Count},{group.src_ports.Count},{group.highOutPort},{group.highInPort},{group.highOutIP},{group.highInIP},{group.highOutConnIP},{group.highInConnIP},{group.listener},{group.speaker}," +
                           $"{group.valHighOutPort},{group.valHighInPort},{group.valHighOutIP},{group.valHighInIP},{group.valHighOutConnIP},{group.valHighInConnIP}," +
                           $"{group.AverageConnectionsPerDestinationIP.ToString(System.Globalization.CultureInfo.InvariantCulture)}," +
                           $"{group.AverageConnectionsPerSourceIP.ToString(System.Globalization.CultureInfo.InvariantCulture)}," +
                           $"{group.AverageConnectionsPerDestinationPort.ToString(System.Globalization.CultureInfo.InvariantCulture)}," +
                           $"{group.AverageConnectionsPerSourcePort.ToString(System.Globalization.CultureInfo.InvariantCulture)}," +
                           $"{group.AverageConnectionsPerUniqueIP.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

                await writer.WriteLineAsync(line);
            }
        }

        public static async Task FormatConnectionsAsJsonAsync(Dictionary<string, ConnectionGroup> ips, string outputPath)
        {
            using var writer = new StreamWriter(outputPath, false, Encoding.UTF8, 65536);
            using var jsonWriter = new JsonTextWriter(writer);
            jsonWriter.Formatting = Formatting.Indented;

            await jsonWriter.WriteStartObjectAsync();

            foreach (var kvp in ips.OrderByDescending(x => x.Value.connections.Count))
            {
                await jsonWriter.WritePropertyNameAsync(kvp.Key);
                await jsonWriter.WriteStartObjectAsync();

                var group = kvp.Value;

                await WriteJsonPropertyAsync(jsonWriter, "TotalConnections", group.connections.Count);
                await WriteJsonPropertyAsync(jsonWriter, "Protocol", group.proto);
                await WriteJsonPropertyAsync(jsonWriter, "Service", group.service);
                await WriteJsonPropertyAsync(jsonWriter, "Classification", group.classification);
                await WriteJsonPropertyAsync(jsonWriter, "UniqueDestinationIPs", group.dest_ips.Count);
                await WriteJsonPropertyAsync(jsonWriter, "UniqueSourceIPs", group.src_ips.Count);
                await WriteJsonPropertyAsync(jsonWriter, "UniqueDestinationPorts", group.dest_ports.Count);
                await WriteJsonPropertyAsync(jsonWriter, "UniqueSourcePorts", group.src_ports.Count);
                await WriteJsonPropertyAsync(jsonWriter, "HighOutgoingPortActivity", group.highOutPort);
                await WriteJsonPropertyAsync(jsonWriter, "HighIncomingPortActivity", group.highInPort);
                await WriteJsonPropertyAsync(jsonWriter, "HighOutgoingIPActivity", group.highOutIP);
                await WriteJsonPropertyAsync(jsonWriter, "HighIncomingIPActivity", group.highInIP);
                await WriteJsonPropertyAsync(jsonWriter, "HighOutgoingConnections", group.highOutConnIP);
                await WriteJsonPropertyAsync(jsonWriter, "HighIncomingConnections", group.highInConnIP);
                await WriteJsonPropertyAsync(jsonWriter, "Listener", group.listener);
                await WriteJsonPropertyAsync(jsonWriter, "Speaker", group.speaker);
                await WriteJsonPropertyAsync(jsonWriter, "OutgoingPortActivityScore", group.valHighOutPort);
                await WriteJsonPropertyAsync(jsonWriter, "IncomingPortActivityScore", group.valHighInPort);
                await WriteJsonPropertyAsync(jsonWriter, "OutgoingIPActivityScore", group.valHighOutIP);
                await WriteJsonPropertyAsync(jsonWriter, "IncomingIPActivityScore", group.valHighInIP);
                await WriteJsonPropertyAsync(jsonWriter, "OutgoingConnectionsScore", group.valHighOutConnIP);
                await WriteJsonPropertyAsync(jsonWriter, "IncomingConnectionsScore", group.valHighInConnIP);
                await WriteJsonPropertyAsync(jsonWriter, "AverageConnectionsPerDestinationIP", group.AverageConnectionsPerDestinationIP);
                await WriteJsonPropertyAsync(jsonWriter, "AverageConnectionsPerSourceIP", group.AverageConnectionsPerSourceIP);
                await WriteJsonPropertyAsync(jsonWriter, "AverageConnectionsPerDestinationPort", group.AverageConnectionsPerDestinationPort);
                await WriteJsonPropertyAsync(jsonWriter, "AverageConnectionsPerSourcePort", group.AverageConnectionsPerSourcePort);
                await WriteJsonPropertyAsync(jsonWriter, "AverageConnectionsPerUniqueIP", group.AverageConnectionsPerUniqueIP);

                await jsonWriter.WriteEndObjectAsync();
            }

            await jsonWriter.WriteEndObjectAsync();
        }

        private static async Task WriteJsonPropertyAsync<T>(JsonTextWriter writer, string propertyName, T value)
        {
            await writer.WritePropertyNameAsync(propertyName);
            await writer.WriteValueAsync(value);
        }
    }
}