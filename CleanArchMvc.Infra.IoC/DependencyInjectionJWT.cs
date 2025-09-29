using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace CleanArchMvc.Infra.IoC;

public static class DependencyInjectionJWT
{
    public static IServiceCollection AddinfraStructureJWT(this IServiceCollection services, IConfiguration configuration)
    {
        //Informar o tipo de autenticação JWT-Bearer
        //Definir o modelo de desafio de autenticação

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        //Habilitar a autenticação JWT usando o esquema e desafio definidos
        //validar o token
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                //valores válidos
                ValidIssuer = configuration["JwT:Issuer"],
                ValidAudience = configuration["JwT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwT:SecretKey"])),
                ClockSkew = TimeSpan.Zero //Zera o tempo de vida de 5 minutos alem do definido
            };
        });

        return services;
    }
}
