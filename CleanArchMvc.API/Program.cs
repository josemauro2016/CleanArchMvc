using CleanArchMvc.Infra.IoC;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddinfraStructureAPI(builder.Configuration);

//Adicionar autenticação ao Token
builder.Services.AddinfraStructureJWT(builder.Configuration);
builder.Services.AddinfraStructureSwagger();
builder.Services.AddControllers();


var app = builder.Build();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseStatusCodePages();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
