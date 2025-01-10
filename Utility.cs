using System.Text.Json;

namespace FlowBreaker
{
    internal class Utility
    {
        public enum Level
        {
            Info,
            Warning,
            Error,
            Task,
            Result,
            Scheduling,
            Indent1,
            Indent2,
            Indent3
        }

        private static ConsoleColor lastColor = ConsoleColor.White;
        public static void Log(string message, Level level = Level.Info)
        {
            string prefix = level switch
            {
                Level.Info => "[INFO] ",
                Level.Warning => "[WARNING] ",
                Level.Error => "[ERROR] ",
                Level.Task => "[TASK] ",
                Level.Result => "[RESULT] ",
                Level.Scheduling => "[Info] ",
                Level.Indent1 => "\t",
                Level.Indent2 => "\t\t",
                Level.Indent3 => "\t\t\t",
                _ => "[INFO] "
            };

            ConsoleColor originalColor = Console.ForegroundColor;
            ConsoleColor newColor = level switch
            {
                Level.Info => ConsoleColor.White,
                Level.Warning => ConsoleColor.Yellow,
                Level.Error => ConsoleColor.Red,
                Level.Task => ConsoleColor.Cyan,
                Level.Result => ConsoleColor.Green,
                Level.Scheduling => ConsoleColor.DarkYellow,
                Level.Indent1 => lastColor,
                Level.Indent2 => lastColor,
                Level.Indent3 => lastColor,
                _ => ConsoleColor.White
            };

            // Set color and print message
            Console.ForegroundColor = newColor;
            Console.WriteLine($"{prefix}{message}");
            Console.ForegroundColor = originalColor;

            // Update lastColor if it's not an indent
            if (level != Level.Indent1 && level != Level.Indent2 && level != Level.Indent3)
            {
                lastColor = newColor;
            }
        }

        public static Dictionary<string, object> LoadConfig(string path)
        {
            Dictionary<string, object> config;

            try
            {
                string jsonString = File.ReadAllText(path);
                config = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading or parsing JSON file: {ex.Message}");
                config = new Dictionary<string, object>();
            }

            return config;
        }
    }
}
