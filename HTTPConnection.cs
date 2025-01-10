using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace FlowBreaker
{
    public class HTTPConnection
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
        public int trans_depth { get; set; }
        public string method { get; set; }
        public string host { get; set; }
        public string uri { get; set; }
        public string user_agent { get; set; }
        public int request_body_len { get; set; }
        public int response_body_len { get; set; }
        public List<string> tags { get; set; }

        public HTTPConnection()
        {
            tags = new List<string>();
        }

        public override string ToString()
        {
            return $"HTTPConnection: {uid} {id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p} {method} {host}{uri}";
        }

        public HTTPConnection Copy()
        {
            return new HTTPConnection
            {
                ts = this.ts,
                uid = this.uid,
                id_orig_h = this.id_orig_h,
                id_orig_p = this.id_orig_p,
                id_resp_h = this.id_resp_h,
                id_resp_p = this.id_resp_p,
                trans_depth = this.trans_depth,
                method = this.method,
                host = this.host,
                uri = this.uri,
                user_agent = this.user_agent,
                request_body_len = this.request_body_len,
                response_body_len = this.response_body_len,
                tags = new List<string>(this.tags)
            };
        }
    }
}