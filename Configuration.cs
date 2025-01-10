using Tomlyn;
using System;
using System.IO;
using System.Collections.Generic;

public class Configuration
{
    private readonly ConfigurationModel _model;

    public Configuration(string path)
    {
        string tomlString = File.ReadAllText(path);
        TomlModelOptions options = new TomlModelOptions
        {
            ConvertPropertyName = name => name
        };
        _model = Toml.ToModel<ConfigurationModel>(tomlString, options: options);
    }

    public T GetValue<T>(string key)
    {
        var value = typeof(ConfigurationModel).GetProperty(key)?.GetValue(_model);

        if (value == null)
            throw new KeyNotFoundException($"Key '{key}' not found in configuration.");

        if (value is T typedValue)
            return typedValue;

        throw new InvalidCastException($"Cannot convert value of key '{key}' to type {typeof(T)}.");
    }
}

public class ConfigurationModel
{
    public List<string> Enabled_Modules { get; set; }
    public BasicParameters BasicParameters { get; set; }
    public PortScanConfig PortScan { get; set; }
    public HostDiscoveryScanConfig HostDiscoveryScan { get; set; }
    public ProtocolSpecificScanConfig ProtocolSpecificScan { get; set; }
    public VersionScanConfig VersionScan { get; set; }
    public ServiceEnumerationConfig ServiceEnumeration { get; set; }
    public BruteForceConfig BruteForce { get; set; }
    public SYNFloodConfig SYNFlood { get; set; }
    public UDPFloodConfig UDPFlood { get; set; }
    public ICMPFloodConfig ICMPFlood { get; set; }
    public DNSAmplificationConfig DNSAmplification { get; set; }
    public NTPAmplificationConfig NTPAmplification { get; set; }
    public SSDPAmplificationConfig SSDPAmplification { get; set; }
    public ConnectionExhaustionConfig ConnectionExhaustion { get; set; }
    public SlowlorisConfig Slowloris { get; set; }

    public BruteForceConfig ButeForce { get; set; }
}

public class BasicParameters
{
    public float Threshold_Outliers_Outgoing_Unique_Port_TCP { get; set; }
    public float Threshold_Outliers_Outgoing_Unique_IP_TCP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_Port_TCP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_IP_TCP { get; set; }
    public float Threshold_Connections_Per_Destination_IP_TCP { get; set; }
    public float Threshold_Connections_Per_Source_IP_TCP { get; set; }
    public float Threshold_Outliers_Outgoing_Unique_Port_UDP { get; set; }
    public float Threshold_Outliers_Outgoing_Unique_IP_UDP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_Port_UDP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_IP_UDP { get; set; }
    public float Threshold_Connections_Per_Destination_IP_UDP { get; set; }
    public float Threshold_Connections_Per_Source_IP_UDP { get; set; }
    public float Threshold_Outliers_Outgoing_Unique_Port_ICMP { get; set; }
    public float Threshold_Outliers_Outgoing_Unique_IP_ICMP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_Port_ICMP { get; set; }
    public float Threshold_Outliers_Incoming_Unique_IP_ICMP { get; set; }
    public float Threshold_Connections_Per_Destination_IP_ICMP { get; set; }
    public float Threshold_Connections_Per_Source_IP_ICMP { get; set; }
}

public class PortScanConfig
{
    public int Connection_Threshold { get; set; }
    public int Unique_Port_Threshold { get; set; }
}

public class HostDiscoveryScanConfig
{
    public int Unique_IP_Threshold { get; set; }
}

public class ProtocolSpecificScanConfig
{
    public int SYN_Scan_Threshold { get; set; }
}

public class VersionScanConfig
{
    public int Connection_Threshold { get; set; }
    public int Min_Port_Number { get; set; }
    public int Max_Bytes_Transferred { get; set; }
    public int[] Common_Ports { get; set; }
}

public class ServiceEnumerationConfig
{
    public int Connection_Threshold { get; set; }
    public int Min_Port_Number { get; set; }
    public int Min_Bytes_Transferred { get; set; }
    public int[] Common_Ports { get; set; }
}

public class BruteForceConfig
{
    public List<int> CommonPorts { get; set; }
    public int MinConnectionsPerPort { get; set; }
    public int PasswordSprayingThreshold { get; set; }
    public double DictionaryAttackIntervalThreshold { get; set; }
}

public class SYNFloodConfig
{
    public int SYNThreshold { get; set; }
}

public class UDPFloodConfig
{
    public int UDPThreshold { get; set; }
}

public class ICMPFloodConfig
{
    public int ICMPThreshold { get; set; }
}

public class DNSAmplificationConfig
{
    public int DNSThreshold { get; set; }
    public float AmplificationFactor { get; set; }
    public int MaxDomainRepetitions { get; set; }
}

public class NTPAmplificationConfig
{
    public int NTPThreshold { get; set; }
    public float AmplificationFactor { get; set; }
}

public class SSDPAmplificationConfig
{
    public int SSDPThreshold { get; set; }
    public float AmplificationFactor { get; set; }
}

public class ConnectionExhaustionConfig
{
    public int ConnectionThreshold { get; set; }
    public int MaxBytes { get; set; }
    public float MinDuration { get; set; }
}

public class SlowlorisConfig
{
    public int HalfOpenThreshold { get; set; }
    public float MinDuration { get; set; }
}

