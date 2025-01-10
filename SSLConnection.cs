using Newtonsoft.Json;
using System;

namespace FlowBreaker
{
    public class SSLConnection
    {
        public DateTime ts { get; set; }
        public string uid { get; set; }
        [JsonProperty("id.orig_h")]
        public string id_orig_h { get; set; }
        [JsonProperty("id.orig_p")]
        public int id_orig_p { get; set; }
        [JsonProperty("id.resp_h")]
        public string id_resp_h { get; set; }
        [JsonProperty("id.resp_p")]
        public int id_resp_p { get; set; }
        public string server_name { get; set; }
        public bool resumed { get; set; }
        public bool established { get; set; }
        public string ssl_history { get; set; }
        public string version { get; set; }
        public string cipher { get; set; }
        public string curve { get; set; }

        public SSLConnection()
        {
        }

        public override string ToString()
        {
            return $"SSLConnection: {uid} {id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p} " +
                   $"Server: {server_name} Version: {version} Cipher: {cipher} Established: {established}";
        }

        public SSLConnection Copy()
        {
            return new SSLConnection
            {
                ts = this.ts,
                uid = this.uid,
                id_orig_h = this.id_orig_h,
                id_orig_p = this.id_orig_p,
                id_resp_h = this.id_resp_h,
                id_resp_p = this.id_resp_p,
                server_name = this.server_name,
                resumed = this.resumed,
                established = this.established,
                ssl_history = this.ssl_history,
                version = this.version,
                cipher = this.cipher,
                curve = this.curve
            };
        }
    }
}