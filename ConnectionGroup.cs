
namespace FlowBreaker
{
    public class ConnectionGroup
    {
        public Dictionary<string, long> src_ips { get; set; }
        public Dictionary<int, long> src_ports { get; set; }
        public Dictionary<string, long> dest_ips { get; set; }
        public Dictionary<int, long> dest_ports { get; set; }
        public Dictionary<string, long> services { get; set; }
        public string proto { get; set; }
        public string service { get; set; }

        public List<Connection> connections { get; set; }


        // Fields are set if ConnectionGroup has higher activity than average
        public bool highOutPort { get; set; }
        public bool highInPort { get; set; }
        public bool highOutIP { get; set; }
        public bool highInIP { get; set; }
        public bool highOutConnIP { get; set; }
        public bool highInConnIP { get; set; }
        public bool listener { get; set; }
        public bool speaker { get; set; }

        public float valHighOutPort { get; set; }
        public float valHighInPort { get; set; }
        public float valHighOutIP { get; set; }
        public float valHighInIP { get; set; }
        public float valHighOutConnIP { get; set; }
        public float valHighInConnIP { get; set; }

        // Fields for activity level
        public float AverageConnectionsPerDestinationIP { get; set; }
        public float AverageConnectionsPerSourceIP { get; set; }
        public float AverageConnectionsPerDestinationPort { get; set; }
        public float AverageConnectionsPerSourcePort { get; set; }
        public float AverageConnectionsPerUniqueIP { get; set; }

        // String fields for further classification
        public string classification { get; set; }
        public string reason { get; set; }

        public ConnectionGroup()
        {
            connections = new List<Connection>();
            src_ports = new Dictionary<int, long>();
            src_ips = new Dictionary<string, long>();
            dest_ports = new Dictionary<int, long>();
            dest_ips = new Dictionary<string, long>();
            services = new Dictionary<string, long>();
            proto = "UNDEF";
            service = "UNDEF";

            highOutPort = false;
            highInPort = false;
            highOutIP = false;
            highInIP = false;
            highOutConnIP = false;
            highInConnIP = false;
            listener = false;
            speaker = false;

            AverageConnectionsPerDestinationIP = -1;
            AverageConnectionsPerSourceIP = -1;

            AverageConnectionsPerDestinationPort = -1;
            AverageConnectionsPerSourcePort = -1;

            AverageConnectionsPerUniqueIP = -1;

            valHighInConnIP = -1;
            valHighOutConnIP = -1;
            valHighInIP = -1;
            valHighOutIP = -1;
            valHighInPort = -1;
            valHighOutPort = -1;


            classification = "UNDEF";
            reason = "UNDEF";
        }

        public bool AddConnection(Connection newConnection)
        {
            // Add connection to group
            if (connections.Contains(newConnection))
                return false;

            else
            {
                // Set all Dictionary values, incrementing if already present
                connections.Add(newConnection);

                if(src_ips.ContainsKey(newConnection.id_orig_h))
                    src_ips[newConnection.id_orig_h]++;
                else
                    src_ips.Add(newConnection.id_orig_h, 1);

                if (src_ports.ContainsKey(newConnection.id_orig_p))
                    src_ports[newConnection.id_orig_p]++;
                else
                    src_ports.Add(newConnection.id_orig_p, 1);

                if (dest_ips.ContainsKey(newConnection.id_resp_h))
                    dest_ips[newConnection.id_resp_h]++;
                else
                    dest_ips.Add(newConnection.id_resp_h, 1);

                if (dest_ports.ContainsKey(newConnection.id_resp_p))
                    dest_ports[newConnection.id_resp_p]++;
                else
                    dest_ports.Add(newConnection.id_resp_p, 1);

                if (newConnection.service != null)
                {
                    if (services.ContainsKey(newConnection.service))
                        services[newConnection.service]++;
                    else
                        services.Add(newConnection.service, 1);
                }

                return true;
            }
        }

        public void setConnections(List<Connection> newConnections)
        {
            connections = newConnections;

            foreach (Connection newConnection in connections)
            {
                if (src_ips.ContainsKey(newConnection.id_orig_h))
                    src_ips[newConnection.id_orig_h]++;
                else
                    src_ips.Add(newConnection.id_orig_h, 1);

                if (src_ports.ContainsKey(newConnection.id_orig_p))
                    src_ports[newConnection.id_orig_p]++;
                else
                    src_ports.Add(newConnection.id_orig_p, 1);

                if (dest_ips.ContainsKey(newConnection.id_resp_h))
                    dest_ips[newConnection.id_resp_h]++;
                else
                    dest_ips.Add(newConnection.id_resp_h, 1);

                if (dest_ports.ContainsKey(newConnection.id_resp_p))
                    dest_ports[newConnection.id_resp_p]++;
                else
                    dest_ports.Add(newConnection.id_resp_p, 1);

                if(newConnection.service != null)
                {
                    if (services.ContainsKey(newConnection.service))
                        services[newConnection.service]++;
                    else
                        services.Add(newConnection.service, 1);
                }
            }

            if(services.Count == 1)
                service = services.First().Key;
            
        }

        public void resetConnections(List<Connection> newConnections)
        {
            
            if (newConnections.Count == 0)
            {
                this.classification = "RESET-INVALID";
                return;
            }

            // Clear existing data
            connections.Clear();
            src_ips.Clear();
            src_ports.Clear();
            dest_ips.Clear();
            dest_ports.Clear();
            services.Clear();

            // Use the existing setConnections method to populate with new data
            setConnections(newConnections);
        }

        public override string ToString()
        {
            return $"ConnectionGroup: {src_ips}:{src_ports} -> {dest_ips}:{dest_ports} {proto} {service} {connections.Count} connections";
        }

        public ConnectionGroup Copy()
        {
            ConnectionGroup copy = new ConnectionGroup
            {
                proto = this.proto,
                service = this.service,
                highOutPort = this.highOutPort,
                highInPort = this.highInPort,
                highOutIP = this.highOutIP,
                highInIP = this.highInIP,
                highOutConnIP = this.highOutConnIP,
                highInConnIP = this.highInConnIP,

                listener = this.listener,
                speaker = this.speaker,
                classification = this.classification,
                reason = this.reason,

                AverageConnectionsPerDestinationIP = this.AverageConnectionsPerDestinationIP,
                AverageConnectionsPerSourceIP = this.AverageConnectionsPerSourceIP,
                AverageConnectionsPerDestinationPort = this.AverageConnectionsPerDestinationPort,
                AverageConnectionsPerSourcePort = this.AverageConnectionsPerSourcePort,
                AverageConnectionsPerUniqueIP = this.AverageConnectionsPerUniqueIP,

                valHighInConnIP = this.valHighInConnIP,
                valHighOutConnIP = this.valHighOutConnIP,
                valHighInIP = this.valHighInIP,
                valHighOutIP = this.valHighOutIP,
                valHighInPort = this.valHighInPort,
                valHighOutPort = this.valHighOutPort
            };

            // Deep copy dictionaries
            copy.src_ips = new Dictionary<string, long>(this.src_ips);
            copy.src_ports = new Dictionary<int, long>(this.src_ports);
            copy.dest_ips = new Dictionary<string, long>(this.dest_ips);
            copy.dest_ports = new Dictionary<int, long>(this.dest_ports);
            copy.services = new Dictionary<string, long>(this.services);

            // Deep copy connections list
            copy.connections = this.connections.Select(c => c.Copy()).ToList();

            return copy;
        }

    }
}
