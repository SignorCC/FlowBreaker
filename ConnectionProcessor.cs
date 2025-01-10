

namespace FlowBreaker
{
    public static class ConnectionProcessor
    {
        // Functions for splitting connections into groups
        public static Dictionary<string, ConnectionGroup> SplitByProtocol(List<Connection> connections)
        {
            Dictionary<string, ConnectionGroup> results = new Dictionary<string, ConnectionGroup>();


            // Sort connections into TCP and UDP groups
            var tcpConnections = connections.Where(c => c.proto.ToUpper() == "TCP").ToList();
            var udpConnections = connections.Where(c => c.proto.ToUpper() == "UDP").ToList();
            var icmpConnections = connections.Where(c => c.proto.ToUpper() == "ICMP").ToList();

            ConnectionGroup tcpGroup = new ConnectionGroup();
            ConnectionGroup udpGroup = new ConnectionGroup();
            ConnectionGroup icmpGroup = new ConnectionGroup();

            tcpGroup.proto = "TCP";
            tcpGroup.setConnections(tcpConnections);

            udpGroup.proto = "UDP";
            udpGroup.setConnections(udpConnections);

            icmpGroup.proto = "ICMP";
            icmpGroup.setConnections(icmpConnections);

            results.Add("TCP", tcpGroup);
            results.Add("UDP", udpGroup);
            results.Add("ICMP", icmpGroup);

            return results;
        }

        public static Dictionary<string, ConnectionGroup> SplitBySourceIP(ConnectionGroup group)
        {
            Dictionary<string, ConnectionGroup> results = new Dictionary<string, ConnectionGroup>();

            // Sort connections by source IP, using origin IP as key, then add them to Dictionary

            var uniqueIPs = group.connections.GroupBy(c => c.id_orig_h)
                .ToDictionary(
                    g => g.Key,
                    g => g.ToList()
                );

            foreach (var IP in uniqueIPs)
            {
                ConnectionGroup newGroup = new ConnectionGroup();
                newGroup.setConnections(IP.Value);
                newGroup.proto = group.proto;
                newGroup.service = group.service;

                results.Add(IP.Key, newGroup);
            }

            return results;
        }

        public static Dictionary<string, ConnectionGroup> SplitByDestinationIP(ConnectionGroup group)
        {
            Dictionary<string, ConnectionGroup> results = new Dictionary<string, ConnectionGroup>();

            // Sort connections by source IP, using origin IP as key, then add them to Dictionary

            var uniqueIPs = group.connections.GroupBy(c => c.id_resp_h)
                .ToDictionary(
                    g => g.Key,
                    g => g.ToList()
                );

            foreach (var IP in uniqueIPs)
            {
                ConnectionGroup newGroup = new ConnectionGroup();
                newGroup.setConnections(IP.Value);
                newGroup.proto = group.proto;
                newGroup.service = group.service;

                results.Add(IP.Key, newGroup);
            }

            return results;
        }

        public static Dictionary<int, ConnectionGroup> SplitBySourcePort(ConnectionGroup group)
        {
            Dictionary<int, ConnectionGroup> results = new Dictionary<int, ConnectionGroup>();

            // Sort connections by source IP, using origin IP as key, then add them to Dictionary

            var uniquePorts = group.connections.GroupBy(c => c.id_orig_p)
                .ToDictionary(
                    g => g.Key,
                    g => g.ToList()
                );

            foreach (var port in uniquePorts)
            {
                ConnectionGroup newGroup = new ConnectionGroup();
                newGroup.setConnections(port.Value);
                newGroup.proto = group.proto;
                newGroup.service = group.service;

                results.Add(port.Key, newGroup);
            }

            return results;
        }

        public static Dictionary<int, ConnectionGroup> SplitByDestinationPort(ConnectionGroup group)
        {
            /// <summary>
            /// <para>Splits a given group by source Port and returns a Dictionary with Ports as Key</para>
            /// </summary>

            Dictionary<int, ConnectionGroup> results = new Dictionary<int, ConnectionGroup>();

            // Sort connections by source IP, using origin IP as key, then add them to Dictionary

            var uniquePorts = group.connections.GroupBy(c => c.id_resp_p)
                .ToDictionary(
                g => g.Key,
                g => g.ToList()
                );

            foreach (var port in uniquePorts)
            {
                ConnectionGroup newGroup = new ConnectionGroup();
                newGroup.setConnections(port.Value);
                newGroup.proto = group.proto;
                newGroup.service = group.service;

                results.Add(port.Key, newGroup);
            }

            return results;
        }

        public static Dictionary<string, ConnectionGroup> SplitByService(ConnectionGroup group)
        {
            /// <summary>
            /// Splits a given group by service and returns a Dictionary with service as Key
            /// </summary>
            ///                       
            Dictionary<string, ConnectionGroup> results = new Dictionary<string, ConnectionGroup>();

            // Sort connections by source IP, using origin IP as key, then add them to Dictionary

            var uniqueServices = group.connections.GroupBy(c => c.service ?? "UNDEF")
                .ToDictionary(
                g => g.Key,
                g => g.ToList()
                );

            foreach (var service in uniqueServices)
            {
                ConnectionGroup newGroup = new ConnectionGroup();
                newGroup.setConnections(service.Value);
                newGroup.proto = group.proto;
                newGroup.service = service.Key;

                results.Add(service.Key, newGroup);
            }

            return results;
        }

        // Functions for calculating averages and flagging outliers
        private static float AverageUniqueDestinationIps(Dictionary<string, ConnectionGroup> group)
        {
            long totalIPs = 0;
            long totalUniqueConnections = 0;

            foreach (KeyValuePair<string, ConnectionGroup> con in group)
            {
                totalIPs += 1;
                totalUniqueConnections += con.Value.dest_ips.Count;
            }

            return (float) totalUniqueConnections / totalIPs;
        }

        private static float AverageConnectionsPerIP(Dictionary<string, ConnectionGroup> group)
        {
            long totalIPs = 0;
            long totalConnections = 0;

            foreach (KeyValuePair<string, ConnectionGroup> con in group)
            {
                totalIPs += 1;
                totalConnections += con.Value.connections.Count();
            }

            return (float)totalConnections / totalIPs;
        }

        private static float AverageUniqueSourceIps(Dictionary<string, ConnectionGroup> group)
        {
            long totalIPs = 0;
            long totalConnections = 0;

            foreach (KeyValuePair<string, ConnectionGroup> con in group)
            {
                // Unique IP address is in string -> how many outgoing connections are associated with it?
                totalIPs += 1;
                totalConnections += con.Value.src_ips.Count;
            }

            return (float) totalConnections / totalIPs;
        }

        private static float AverageUniqueDestinationPorts(Dictionary<string, ConnectionGroup> group)
        {
            long totalIPs = 0;
            long totalUniquePorts = 0;

            foreach (KeyValuePair<string, ConnectionGroup> con in group)
            {
                totalIPs += 1;
                totalUniquePorts += con.Value.dest_ports.Count;
            }

            return (float)totalUniquePorts / totalIPs;
        }

        private static float AverageUniqueSourcePorts(Dictionary<string, ConnectionGroup> group)
        {
            long totalIPs = 0;
            long totalUniquePorts = 0;

            foreach (KeyValuePair<string, ConnectionGroup> con in group)
            {
                totalIPs += 1;
                totalUniquePorts += con.Value.src_ports.Count;
            }

            return (float)totalUniquePorts / totalIPs;
        }

        public static Dictionary<string, ConnectionGroup> FlagOutliersOutgoingUnique(Dictionary<string, ConnectionGroup> input, float ipThreshold, float portThreshold)
        {
            var results = input;

            float addressAvg = AverageUniqueDestinationIps(input);
            float portAvg = AverageUniqueDestinationPorts(input);

            foreach (KeyValuePair<string, ConnectionGroup> con in input)
            {
                int uniqueConnections = con.Value.dest_ips.Count;

                if (uniqueConnections >= addressAvg * ipThreshold)
                    results[con.Key].highOutIP = true;

                int uniquePorts = con.Value.dest_ports.Count;

                if (uniquePorts >= portAvg * portThreshold)
                    results[con.Key].highOutPort = true;
            }

            return results;
        }

        public static Dictionary<string, ConnectionGroup> FlagOutliersOutgoingConnections(Dictionary<string, ConnectionGroup> input, float ipThreshold)
        {
            var results = input;

            float addressAvg = AverageConnectionsPerIP(input);

            foreach (KeyValuePair<string, ConnectionGroup> con in input)
            {
                if (con.Value.connections.Where(c => c.id_orig_h == con.Key)
                    .ToList()
                    .Count() >= addressAvg * ipThreshold)
                    results[con.Key].highOutConnIP = true;
                
            }

            return results;
        }

        public static Dictionary<string, ConnectionGroup> FlagOutliersIncomingConnections(Dictionary<string, ConnectionGroup> input, float ipThreshold)
        {
            var results = input;

            float addressAvg = AverageConnectionsPerIP(input);

            foreach (KeyValuePair<string, ConnectionGroup> con in input)
            {
                if (con.Value.connections.Where(c => c.id_resp_h == con.Key)
                    .ToList()
                    .Count() >= addressAvg * ipThreshold)
                    results[con.Key].highInConnIP = true;

            }

            return results;
        }

        public static Dictionary<string, ConnectionGroup> FlagOutliersIncomingUnique(Dictionary<string, ConnectionGroup> input, float ipThreshold, float portThreshold)
        {
            var results = input;

            float addressAvg = AverageUniqueSourceIps(input);
            float portAvg = AverageUniqueSourcePorts(input);

            foreach (KeyValuePair<string, ConnectionGroup> con in input)
            {
                if (con.Value.src_ips.Count() >= addressAvg * ipThreshold)
                    results[con.Key].highInIP = true;

                if (con.Value.src_ports.Count() >= portAvg * portThreshold)
                    results[con.Key].highInPort = true;
            }

            return results;
        }

        public static (Dictionary<string, ConnectionGroup> sortBySource, Dictionary<string, ConnectionGroup> sortByDestination) FlagSpeakerListener(Dictionary<string, ConnectionGroup> sortBySource, Dictionary<string, ConnectionGroup> sortByDestination)
        {
            // Decide whether there are more incoming or outgoing connections
            foreach (KeyValuePair<string, ConnectionGroup> con in sortBySource)
            {

                // If no direct comparison possible, assume speaker
                if (!sortByDestination.ContainsKey(con.Key))
                {
                    con.Value.speaker = true;
                    continue;
                }
                    
                if (con.Value.connections.Where(c => c.id_orig_h == con.Key).Count() >= sortByDestination[con.Key].connections.Where(c => c.id_resp_h == con.Key).Count())
                {
                    con.Value.speaker = true;
                    sortByDestination[con.Key].listener = true;
                }

                else
                {
                    con.Value.listener = true;
                    sortByDestination[con.Key].speaker = true;
                }

            }

            // If there are connections in sortByDestination that are not in sortBySource, they are listeners
            foreach (KeyValuePair<string, ConnectionGroup> con in sortByDestination)
                if(!sortBySource.ContainsKey(con.Key))
                    con.Value.listener = true;
                        

            return (sortBySource, sortByDestination);
        }

        public static (Dictionary<string, ConnectionGroup> sortBySource, Dictionary<string, ConnectionGroup> sortByDestination) SetFlags(Dictionary<string, ConnectionGroup> sortBySource, Dictionary<string, ConnectionGroup> sortByDestination, Configuration config, string protocol)
        {
            var basicParams = config.GetValue<BasicParameters>("BasicParameters");

            float Threshold_Outliers_Outgoing_Unique_Port;
            float Threshold_Outliers_Outgoing_Unique_IP;
            float Threshold_Outliers_Incoming_Unique_Port;
            float Threshold_Outliers_Incoming_Unique_IP;
            float Threshold_Connections_Per_Destination_IP;
            float Threshold_Connections_Per_Source_IP;

            // Set thresholds based on protocol
            switch (protocol)
            {
                case "TCP":
                    Threshold_Outliers_Outgoing_Unique_Port = basicParams.Threshold_Outliers_Outgoing_Unique_Port_TCP;
                    Threshold_Outliers_Outgoing_Unique_IP = basicParams.Threshold_Outliers_Outgoing_Unique_IP_TCP;
                    Threshold_Outliers_Incoming_Unique_Port = basicParams.Threshold_Outliers_Incoming_Unique_Port_TCP;
                    Threshold_Outliers_Incoming_Unique_IP = basicParams.Threshold_Outliers_Incoming_Unique_IP_TCP;
                    Threshold_Connections_Per_Destination_IP = basicParams.Threshold_Connections_Per_Destination_IP_TCP;
                    Threshold_Connections_Per_Source_IP = basicParams.Threshold_Connections_Per_Source_IP_TCP;
                    break;
                case "UDP":
                    Threshold_Outliers_Outgoing_Unique_Port = basicParams.Threshold_Outliers_Outgoing_Unique_Port_UDP;
                    Threshold_Outliers_Outgoing_Unique_IP = basicParams.Threshold_Outliers_Outgoing_Unique_IP_UDP;
                    Threshold_Outliers_Incoming_Unique_Port = basicParams.Threshold_Outliers_Incoming_Unique_Port_UDP;
                    Threshold_Outliers_Incoming_Unique_IP = basicParams.Threshold_Outliers_Incoming_Unique_IP_UDP;
                    Threshold_Connections_Per_Destination_IP = basicParams.Threshold_Connections_Per_Destination_IP_UDP;
                    Threshold_Connections_Per_Source_IP = basicParams.Threshold_Connections_Per_Source_IP_UDP;
                    break;
                case "ICMP":
                    Threshold_Outliers_Outgoing_Unique_Port = basicParams.Threshold_Outliers_Outgoing_Unique_Port_ICMP;
                    Threshold_Outliers_Outgoing_Unique_IP = basicParams.Threshold_Outliers_Outgoing_Unique_IP_ICMP;
                    Threshold_Outliers_Incoming_Unique_Port = basicParams.Threshold_Outliers_Incoming_Unique_Port_ICMP;
                    Threshold_Outliers_Incoming_Unique_IP = basicParams.Threshold_Outliers_Incoming_Unique_IP_ICMP;
                    Threshold_Connections_Per_Destination_IP = basicParams.Threshold_Connections_Per_Destination_IP_ICMP;
                    Threshold_Connections_Per_Source_IP = basicParams.Threshold_Connections_Per_Source_IP_ICMP;
                    break;
                default:
                    throw new ArgumentException("Invalid protocol specified");
            }

            // Calculate averages
            float avgUniqueDestIPs = AverageUniqueDestinationIps(sortBySource); // How many unique destination IPs did a source IP connect to on average
            float avgUniqueSrcIPs = AverageUniqueSourceIps(sortByDestination); // How many unique source IPs did a destination IP connect to on average

            float avgUniqueDestPorts = AverageUniqueDestinationPorts(sortByDestination);
            float avgUniqueSrcPorts = AverageUniqueSourcePorts(sortBySource);

            float avgConnectionsPerDestIP = AverageConnectionsPerIP(sortBySource); // How many connections were initiated on average
            float avgConnectionsPerSrcIP = AverageConnectionsPerIP(sortByDestination); // How many connections were received on average

            // Print out average values to Console
            Utility.Log("Average values for " + protocol + " connections", Utility.Level.Result);
            Utility.Log("Average unique destination IPs: " + avgUniqueDestIPs, Utility.Level.Indent1);
            Utility.Log("Average unique source IPs: " + avgUniqueSrcIPs, Utility.Level.Indent1);
            Utility.Log("Average unique destination ports: " + avgUniqueDestPorts, Utility.Level.Indent1);
            Utility.Log("Average unique source ports: " + avgUniqueSrcPorts, Utility.Level.Indent1);
            Utility.Log("Average connections per destination IP: " + avgConnectionsPerDestIP, Utility.Level.Indent1);
            Utility.Log("Average connections per source IP: " + avgConnectionsPerSrcIP, Utility.Level.Indent1);

            // In sortBySource dest_ips >= 1, src_ips = 1
            foreach (var kvp in sortBySource)
            {
                // Flag outliers
                if (kvp.Value.src_ports.Count() >= avgUniqueSrcPorts * Threshold_Outliers_Outgoing_Unique_Port)
                    kvp.Value.highOutPort = true;

                if (kvp.Value.dest_ips.Count() >= avgUniqueDestIPs * Threshold_Outliers_Outgoing_Unique_IP)
                    kvp.Value.highOutIP = true;

                if (kvp.Value.connections.Count() >= avgConnectionsPerDestIP * Threshold_Connections_Per_Destination_IP)
                    kvp.Value.highOutConnIP = true;


                // Averaging connections
                kvp.Value.AverageConnectionsPerSourceIP = (float)kvp.Value.connections.Count();
                kvp.Value.AverageConnectionsPerDestinationIP = (float) kvp.Value.connections.Count() / kvp.Value.dest_ips.Count(); ;
                kvp.Value.AverageConnectionsPerSourcePort = (float)kvp.Value.connections.Count() / kvp.Value.src_ports.Count();
                kvp.Value.AverageConnectionsPerDestinationPort = (float)kvp.Value.connections.Count() / kvp.Value.dest_ports.Count();
                kvp.Value.AverageConnectionsPerUniqueIP = (float)kvp.Value.connections.Count() / kvp.Value.dest_ips.Count();

                // Set calculations in other Dictionary as well
                if (sortByDestination.ContainsKey(kvp.Key))
                {
                    sortByDestination[kvp.Key].highOutPort = kvp.Value.highOutPort;
                    sortByDestination[kvp.Key].highOutIP = kvp.Value.highOutIP;
                    sortByDestination[kvp.Key].highOutConnIP = kvp.Value.highOutConnIP;
                }

            }

            // In sortByDestination src_ips >= 1, dest_ips = 1
            foreach (var kvp in sortByDestination)
            {
                // Flag outliers
                if (kvp.Value.dest_ports.Count() >= avgUniqueDestPorts * Threshold_Outliers_Incoming_Unique_Port)
                    kvp.Value.highInPort = true;

                if (kvp.Value.src_ips.Count() >= avgUniqueSrcIPs * Threshold_Outliers_Incoming_Unique_IP)
                    kvp.Value.highInIP = true;

                if (kvp.Value.connections.Count() >= avgConnectionsPerSrcIP * Threshold_Connections_Per_Source_IP)
                    kvp.Value.highInConnIP = true;

                // Averaging connections             
                kvp.Value.AverageConnectionsPerDestinationIP = (float)kvp.Value.connections.Count();
                kvp.Value.AverageConnectionsPerSourceIP = (float)kvp.Value.connections.Count() / kvp.Value.src_ips.Count();
                kvp.Value.AverageConnectionsPerSourcePort = (float) kvp.Value.connections.Count() / kvp.Value.src_ports.Count();
                kvp.Value.AverageConnectionsPerDestinationPort = (float) kvp.Value.connections.Count() / kvp.Value.dest_ports.Count();
                kvp.Value.AverageConnectionsPerUniqueIP = (float)kvp.Value.connections.Count() / kvp.Value.src_ips.Count();

                // Set calculations in other Dictionary as well
                if (sortBySource.ContainsKey(kvp.Key))
                {
                    sortBySource[kvp.Key].highInPort = kvp.Value.highInPort;
                    sortBySource[kvp.Key].highInIP = kvp.Value.highInIP;
                    sortBySource[kvp.Key].highInConnIP = kvp.Value.highInConnIP;
                }  

            }


            // Set speaker and listener flags
            (sortBySource, sortByDestination) = FlagSpeakerListener(sortBySource, sortByDestination);

            return (sortBySource, sortByDestination);
        }
    }
}
