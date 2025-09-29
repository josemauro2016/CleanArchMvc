using CleanArchMvc.Domain.Account;
using CleanArchMvc.Infra.IoC;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddinfraStructure(builder.Configuration);

//Adicionando servi�os ao container
builder.Services.AddControllersWithViews();


var app = builder.Build();

//Configurando canos de requisi��es HTTP
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//ISeedUserRoleInitial.SeedRoles();
//SeedUserRoleInitial.SeedUsers();
SeedUserRoles(app);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

void SeedUserRoles(IApplicationBuilder app)
{
    using (var serviceScope = app.ApplicationServices.CreateScope())
    {
        var seed = serviceScope.ServiceProvider.GetService<ISeedUserRoleInitial>();
        seed.SeedUsers();
        seed.SeedRoles();
    }
}
