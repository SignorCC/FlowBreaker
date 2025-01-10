using Newtonsoft.Json;
using System;

namespace FlowBreaker
{
    public class SSHConnection
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
        public int auth_attempts { get; set; }
        public string direction { get; set; }
        public string client { get; set; }

        public SSHConnection()
        {
        }

        public override string ToString()
        {
            return $"SSHConnection: {uid} {id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p} Direction: {direction} Client: {client}";
        }

        public SSHConnection Copy()
        {
            return new SSHConnection
            {
                ts = this.ts,
                uid = this.uid,
                id_orig_h = this.id_orig_h,
                id_orig_p = this.id_orig_p,
                id_resp_h = this.id_resp_h,
                id_resp_p = this.id_resp_p,
                auth_attempts = this.auth_attempts,
                direction = this.direction,
                client = this.client
            };
        }
    }
}