using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using XSystem.Security.Cryptography;

namespace FlowBreaker
{
    public enum Classification
    {
        Normal = 1,
        Suspicious,
        Malicious
    }

    public class Connection
    {
        // Most important fields
        public string uid { get; set; }
        [JsonProperty("id.orig_h")]
        public string id_orig_h { get; set; }
        [JsonProperty("id.orig_p")]
        public int id_orig_p { get; set; }
        [JsonProperty("id.resp_h")]
        public string id_resp_h { get; set; }
        [JsonProperty("id.resp_p")]
        public int id_resp_p { get; set; }
        public string proto { get; set; }
        public string service { get; set; }
        public DateTime ts { get; set; }

        // Less important fields
        public double duration { get; set; }
        public long orig_bytes { get; set; }
        public long resp_bytes { get; set; }
        public string conn_state { get; set; }
        public bool local_orig { get; set; }
        public bool local_resp { get; set; }
        public long missed_bytes { get; set; }
        public string history { get; set; }
        public long orig_pkts { get; set; }
        public long orig_ip_bytes { get; set; }
        public long resp_pkts { get; set; }
        public long resp_ip_bytes { get; set; }

        // Custom fields
        public Classification classification { get; set; }
        public string customHash { get; set; }

        public Connection()
        {
        }

        public void generateHash()
        {
            // Generate unique SHA1 hash based on all connection properties except uid
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                string allFields = string.Join("|",
                    id_orig_h,
                    id_orig_p.ToString(),
                    id_resp_h,
                    id_resp_p.ToString(),
                    proto,
                    service,
                    ts.ToString("O"),
                    duration.ToString("G17"),
                    orig_bytes.ToString(),
                    resp_bytes.ToString(),
                    conn_state,
                    local_orig.ToString(),
                    local_resp.ToString(),
                    missed_bytes.ToString(),
                    history,
                    orig_pkts.ToString(),
                    orig_ip_bytes.ToString(),
                    resp_pkts.ToString(),
                    resp_ip_bytes.ToString(),
                    classification.ToString() ?? "null"
                );

                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(allFields));
                customHash = BitConverter.ToString(hash).Replace("-", "");
            }
        }

        override public string ToString()
        {
            return $"Connection: {uid} {id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p} {proto} {service} {history} {ts}";
        }

        public Connection Copy()
        {
            return new Connection
            {
                uid = this.uid,
                id_orig_h = this.id_orig_h,
                id_orig_p = this.id_orig_p,
                id_resp_h = this.id_resp_h,
                id_resp_p = this.id_resp_p,
                proto = this.proto,
                service = this.service,
                ts = this.ts,
                duration = this.duration,
                orig_bytes = this.orig_bytes,
                resp_bytes = this.resp_bytes,
                conn_state = this.conn_state,
                local_orig = this.local_orig,
                local_resp = this.local_resp,
                missed_bytes = this.missed_bytes,
                history = this.history,
                orig_pkts = this.orig_pkts,
                orig_ip_bytes = this.orig_ip_bytes,
                resp_pkts = this.resp_pkts,
                resp_ip_bytes = this.resp_ip_bytes,
                classification = this.classification,
                customHash = this.customHash
            };
        }

    }
}
