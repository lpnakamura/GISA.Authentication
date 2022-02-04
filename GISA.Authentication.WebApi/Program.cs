using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using System.IO;
using System.Reflection;

namespace GISA.Authentication.WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var configurationBuilder = new ConfigurationBuilder()
                         .AddJsonFile($"appsettings.json", true)
                         .Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configurationBuilder)
                .CreateLogger();

            try
            {
                Log.Information("Application Starting.");
                CreateHostBuilder(args).Build().Run();
            }
            catch (Exception exception)
            {
                Log.Fatal(exception, "The Application failed to start.");
            }
            finally
            {
                Log.CloseAndFlush();
            }

            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>())
            .ConfigureAppConfiguration((hostContext, configuration) =>
            {
                configuration.SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
                configuration.AddJsonFile("appsettings.json", optional: true);
                configuration.AddEnvironmentVariables().Build();
            });
    }
}
