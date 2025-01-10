using Newtonsoft.Json;

namespace FlowBreaker
{
    public static class LogHandler
    {
        public static async Task<List<Connection>> ParseConnectionAsync(string filePath)
        {
            try
            {
                var connections = new List<Connection>();

                using (var fileStream = File.OpenRead(filePath))
                using (var streamReader = new StreamReader(fileStream))
                using (var jsonReader = new JsonTextReader(streamReader) { CloseInput = false, SupportMultipleContent = true })
                {
                    var serializer = new JsonSerializer();

                    while (await jsonReader.ReadAsync())
                    {
                        if (jsonReader.TokenType == JsonToken.StartObject)
                        {
                            var connection = serializer.Deserialize<Connection>(jsonReader);
                            connections.Add(connection);
                        }
                    }
                }

                return connections;
            }

            catch
            {
                return new List<Connection>();
            }
        }

        public static async Task<List<DNSConnection>> ParseDNSAsync(string filePath)
        {
            try
            {
                var connections = new List<DNSConnection>();

                using (var fileStream = File.OpenRead(filePath))
                using (var streamReader = new StreamReader(fileStream))
                using (var jsonReader = new JsonTextReader(streamReader) { CloseInput = false, SupportMultipleContent = true })
                {
                    var serializer = new JsonSerializer();

                    while (await jsonReader.ReadAsync())
                    {
                        if (jsonReader.TokenType == JsonToken.StartObject)
                        {
                            var connection = serializer.Deserialize<DNSConnection>(jsonReader);
                            connections.Add(connection);
                        }
                    }
                }

                return connections;
            }

            catch
            {
                return new List<DNSConnection>();
            }

        }

        public static async Task<List<SSLConnection>> ParseSSLAsync(string filePath)
        {
            try
            {
                var connections = new List<SSLConnection>();

                using (var fileStream = File.OpenRead(filePath))
                using (var streamReader = new StreamReader(fileStream))
                using (var jsonReader = new JsonTextReader(streamReader) { CloseInput = false, SupportMultipleContent = true })
                {
                    var serializer = new JsonSerializer();

                    while (await jsonReader.ReadAsync())
                    {
                        if (jsonReader.TokenType == JsonToken.StartObject)
                        {
                            var connection = serializer.Deserialize<SSLConnection>(jsonReader);
                            connections.Add(connection);
                        }
                    }
                }

                return connections;
            }

            catch
            {
                return new List<SSLConnection>();
            }

        }

        public static async Task<List<SSHConnection>> ParseSSHAsync(string filePath)
        {
            try
            {
                var connections = new List<SSHConnection>();

                using (var fileStream = File.OpenRead(filePath))
                using (var streamReader = new StreamReader(fileStream))
                using (var jsonReader = new JsonTextReader(streamReader) { CloseInput = false, SupportMultipleContent = true })
                {
                    var serializer = new JsonSerializer();

                    while (await jsonReader.ReadAsync())
                    {
                        if (jsonReader.TokenType == JsonToken.StartObject)
                        {
                            var connection = serializer.Deserialize<SSHConnection>(jsonReader);
                            connections.Add(connection);
                        }
                    }
                }

                return connections;
            }

            catch
            {
                return new List<SSHConnection>();
            }   

        }

        public static async Task<List<HTTPConnection>> ParseHTTPAsync(string filePath)
        {
            try
            {
                var connections = new List<HTTPConnection>();

                using (var fileStream = File.OpenRead(filePath))
                using (var streamReader = new StreamReader(fileStream))
                using (var jsonReader = new JsonTextReader(streamReader) { CloseInput = false, SupportMultipleContent = true })
                {
                    var serializer = new JsonSerializer();

                    while (await jsonReader.ReadAsync())
                    {
                        if (jsonReader.TokenType == JsonToken.StartObject)
                        {
                            var connection = serializer.Deserialize<HTTPConnection>(jsonReader);
                            connections.Add(connection);
                        }
                    }
                }

                return connections;
            }

            catch
            { return new List<HTTPConnection>(); }
            
        }



    }
}
