using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace FlowBreaker
{
    public class DNSConnection
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
        public string proto { get; set; }
        public int trans_id { get; set; }
        public string query { get; set; }
        public int rcode { get; set; }
        public string rcode_name { get; set; }
        public bool AA { get; set; }
        public bool TC { get; set; }
        public bool RD { get; set; }
        public bool RA { get; set; }
        public int Z { get; set; }
        public List<string> answers { get; set; }
        public List<double> TTLs { get; set; }
        public bool rejected { get; set; }

        public DNSConnection()
        {
            answers = new List<string>();
            TTLs = new List<double>();
        }

        public override string ToString()
        {
            return $"DNSConnection: {uid} {id_orig_h}:{id_orig_p} -> {id_resp_h}:{id_resp_p} {proto} Query: {query} Answers: {answers.Count}";
        }

        public DNSConnection Copy()
        {
            return new DNSConnection
            {
                ts = this.ts,
                uid = this.uid,
                id_orig_h = this.id_orig_h,
                id_orig_p = this.id_orig_p,
                id_resp_h = this.id_resp_h,
                id_resp_p = this.id_resp_p,
                proto = this.proto,
                trans_id = this.trans_id,
                query = this.query,
                rcode = this.rcode,
                rcode_name = this.rcode_name,
                AA = this.AA,
                TC = this.TC,
                RD = this.RD,
                RA = this.RA,
                Z = this.Z,
                answers = new List<string>(this.answers),
                TTLs = new List<double>(this.TTLs),
                rejected = this.rejected
            };
        }
    }
}