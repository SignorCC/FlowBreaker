using Newtonsoft.Json;
using System.Text;
using XAct;

namespace FlowBreaker
{
    public static class Formatter
    {
        public static string FormatConnections(Dictionary<string, ConnectionGroup> ips)
        {
            StringBuilder sb = new StringBuilder();

            // Sort IPs by total number of connections (descending order)
            var sortedIPs = ips.OrderByDescending(kvp => kvp.Value.connections.Count);

            foreach (var kvp in sortedIPs)
            {
                string ip = kvp.Key;
                ConnectionGroup group = kvp.Value;
                bool isSourceIP = false;

                sb.AppendLine($"IP: {ip}");
                sb.AppendLine($"Total Connections: {group.connections.Count}");
                sb.AppendLine($"Protocol: {group.proto}");
                sb.AppendLine($"Service: {group.service}");

                sb.AppendLine($"Classification: {group.classification}");
                if (group.classification!= "UNDEF")
                     sb.AppendLine($"Reason:\n{group.reason}");

                // Connection Summary, ingoing and outgoing
                sb.AppendLine("Connection Summary:");

                // Destination IPs - skip if we are sorting by destination IP
                if (!(group.dest_ips.First().Key == ip && group.dest_ips.Count == 1))
                {
                    isSourceIP = true;

                    sb.AppendLine($"\tUnique Destination IPs: {group.dest_ips.Count}");
                    sb.AppendLine("\tDestination IPs:");
                    foreach (var destIP in group.dest_ips.OrderByDescending(x => x.Value))
                        sb.AppendLine($"\t\t{destIP.Key}: {destIP.Value} connections");
                }


                // Source IPs - skip if we are sorting by source IP
                if (!(group.src_ips.First().Key == ip && group.src_ips.Count == 1))
                {

                    sb.AppendLine($"\tUnique Source IPs: {group.src_ips.Count}");
                    sb.AppendLine("\tSource IPs:");
                    foreach (var srcIP in group.src_ips.OrderByDescending(x => x.Value))
                        sb.AppendLine($"\t\t{srcIP.Key}: {srcIP.Value} connections");
                }

                // Unique Ports
                sb.AppendLine($"\tUnique Destination Ports: {group.dest_ports.Count}");
                sb.AppendLine("\t\tDestination Ports:");
                foreach (var destPort in group.dest_ports.OrderBy(x => x.Key))
                {
                    sb.AppendLine($"\t\t\t{destPort.Key}: {destPort.Value} connections");

                    foreach (var conn in group.connections)
                    {
                        if (isSourceIP)
                            if (conn.id_resp_h == ip && conn.id_resp_p == destPort.Key);
                                //sb.AppendLine($"\t\t\t\t{conn.ToString()})");
                        else
                            if (conn.id_orig_h == ip && conn.id_resp_p == destPort.Key);
                                //sb.AppendLine($"\t\t\t\t{conn.ToString()})");
                    }

                }
                   

                sb.AppendLine($"\tUnique Source Ports: {group.src_ports.Count}");
                sb.AppendLine("\t\tSource Ports:");
                foreach (var srcPort in group.src_ports.OrderBy(x => x.Key))
                {
                    sb.AppendLine($"\t\t\t{srcPort.Key}: {srcPort.Value} connections");

                    foreach(var conn in group.connections)
                    {
                        if(isSourceIP)
                            if (conn.id_resp_h == ip && conn.id_orig_p == srcPort.Key);
                                //sb.AppendLine($"\t\t\t\t{conn.ToString()})");
                        else
                            if (conn.id_orig_h == ip && conn.id_orig_p == srcPort.Key);
                                //sb.AppendLine($"\t\t\t\t{conn.ToString()})");
                    }
                        
                }
                    

                // Services
                sb.AppendLine("Services:");
                foreach (var service in group.services.OrderByDescending(x => x.Value))
                {
                    sb.AppendLine($"\t{service.Key}: {service.Value} connections");
                }

                // Activity flags
                sb.AppendLine("Activity Flags:");
                sb.AppendLine($"\tHigh Outgoing Port Activity: {group.highOutPort}");
                sb.AppendLine($"\tHigh Incoming Port Activity: {group.highInPort}");
                sb.AppendLine($"\tHigh Outgoing IP Activity: {group.highOutIP}");
                sb.AppendLine($"\tHigh Incoming IP Activity: {group.highInIP}");
                sb.AppendLine($"\tHigh Number of Outgoing Connections: {group.highOutConnIP}");
                sb.AppendLine($"\tHigh Number of Incoming Connections: {group.highInConnIP}");
                sb.AppendLine($"\tListener: {group.listener}");
                sb.AppendLine($"\tSpeaker: {group.speaker}");

                // Flagging Scores
                sb.AppendLine("Flagging Scores (Current Value/Average Value):");
                sb.AppendLine($"\tOutgoing Port Activity: {group.valHighOutPort}");
                sb.AppendLine($"\tIncoming Port Activity: {group.valHighInPort}");
                sb.AppendLine($"\tOutgoing IP Activity: {group.valHighOutIP}");
                sb.AppendLine($"\tIncoming IP Activity: {group.valHighInIP}");
                sb.AppendLine($"\tOutgoing Connections: {group.valHighOutConnIP}");
                sb.AppendLine($"\tIncoming Connections: {group.valHighInConnIP}");

                // Average Values
                sb.AppendLine("Average Values:");
                sb.AppendLine($"\tConnections per Destination IP: {group.AverageConnectionsPerDestinationIP}");
                sb.AppendLine($"\tConnections per Source IP: {group.AverageConnectionsPerSourceIP}");
                sb.AppendLine($"\tConnections per Destination Port: {group.AverageConnectionsPerDestinationPort}");
                sb.AppendLine($"\tConnections per Source Port: {group.AverageConnectionsPerSourcePort}");
                sb.AppendLine($"\tConnections per Unique IP: {group.AverageConnectionsPerUniqueIP}");

                sb.AppendLine(new string('-', 80)); // Separator between IPs
            }

            return sb.ToString();
        }

        public static string FormatConnectionsAsCsv(Dictionary<string, ConnectionGroup> ips)
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP,TotalConnections,Protocol,Service,Classification,UniqueDestinationIPs,UniqueSourceIPs,UniqueDestinationPorts,UniqueSourcePorts,HighOutgoingPortActivity,HighIncomingPortActivity,HighOutgoingIPActivity,HighIncomingIPActivity,HighOutgoingConnections,HighIncomingConnections,Listener,Speaker,OutgoingPortActivityScore,IncomingPortActivityScore,OutgoingIPActivityScore,IncomingIPActivityScore,OutgoingConnectionsScore,IncomingConnectionsScore,AvgConnectionsPerDestIP,AvgConnectionsPerSourceIP,AvgConnectionsPerDestPort,AvgConnectionsPerSourcePort,AvgConnectionsPerUniqueIP");

            foreach (var kvp in ips.OrderByDescending(x => x.Value.connections.Count))
            {
                var group = kvp.Value;
                string averageValues = $"{group.AverageConnectionsPerDestinationIP.ToString().Replace(",", ".")}," +
                    $"{group.AverageConnectionsPerSourceIP.ToString().Replace(",", ".")}," +
                    $"{group.AverageConnectionsPerDestinationPort.ToString().Replace(",", ".")}," +
                    $"{group.AverageConnectionsPerSourcePort.ToString().Replace(",", ".")}," +
                    $"{group.AverageConnectionsPerUniqueIP.ToString().Replace(",", ".")}";

                sb.AppendLine($"{kvp.Key},{group.connections.Count},{group.proto},{group.service},{group.classification},{group.dest_ips.Count},{group.src_ips.Count},{group.dest_ports.Count},{group.src_ports.Count},{group.highOutPort},{group.highInPort},{group.highOutIP},{group.highInIP},{group.highOutConnIP},{group.highInConnIP},{group.listener},{group.speaker}," +
                   $"{group.valHighOutPort},{group.valHighInPort},{group.valHighOutIP},{group.valHighInIP},{group.valHighOutConnIP},{group.valHighInConnIP}," +
                   $"{averageValues}");
            }

            return sb.ToString();
        }

        public static string FormatConnectionsAsJson(Dictionary<string, ConnectionGroup> ips)
        {
            var jsonObject = ips.ToDictionary(
                kvp => kvp.Key,
                kvp => new
                {
                    TotalConnections = kvp.Value.connections.Count,
                    kvp.Value.proto,
                    kvp.Value.service,
                    kvp.Value.classification,
                    UniqueDestinationIPs = kvp.Value.dest_ips.Count,
                    UniqueSourceIPs = kvp.Value.src_ips.Count,
                    UniqueDestinationPorts = kvp.Value.dest_ports.Count,
                    UniqueSourcePorts = kvp.Value.src_ports.Count,
                    kvp.Value.highOutPort,
                    kvp.Value.highInPort,
                    kvp.Value.highOutIP,
                    kvp.Value.highInIP,
                    kvp.Value.highOutConnIP,
                    kvp.Value.highInConnIP,
                    kvp.Value.listener,
                    kvp.Value.speaker,
                    OutgoingPortActivityScore = kvp.Value.valHighOutPort,
                    IncomingPortActivityScore = kvp.Value.valHighInPort,
                    OutgoingIPActivityScore = kvp.Value.valHighOutIP,
                    IncomingIPActivityScore = kvp.Value.valHighInIP,
                    OutgoingConnectionsScore = kvp.Value.valHighOutConnIP,
                    IncomingConnectionsScore = kvp.Value.valHighInConnIP,
                    kvp.Value.AverageConnectionsPerDestinationIP,
                    kvp.Value.AverageConnectionsPerSourceIP,
                    kvp.Value.AverageConnectionsPerDestinationPort,
                    kvp.Value.AverageConnectionsPerSourcePort,
                    kvp.Value.AverageConnectionsPerUniqueIP
                }
            );

            return JsonConvert.SerializeObject(jsonObject, Formatting.Indented);
        }
    }
}
