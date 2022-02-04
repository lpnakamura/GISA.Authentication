using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using GISA.Authentication.Infra.IoC;

namespace GISA.Authentication.WebApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddInfrastructure(Configuration);
            services.ConfigureCors(Configuration);
            services.AddAutoMapper();
            services.AddIdentity();
            services.AddHealthChecks();
            services.AddSwaggerDocumentation(Configuration);
            services.AddApiVersion();
            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IApiVersionDescriptionProvider versionProvider)
        {
            if (env.IsDevelopment()) app.UseDeveloperExceptionPage();
            app.UseAppCors();
            app.UseHealthChecks("/health");
            app.AddSwaggerApplication(versionProvider);
            app.UseApiVersioning();
            app.UseSerilogExtension();
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapControllers());
        }
    }
}