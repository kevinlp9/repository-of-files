// Carlos Pineda G. 2025 - SaberLibre Backend Unificado
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Data;
using MySql.Data.MySqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace t8vs2022630077
{
    // Modelos de datos
    public class Archivo
    {
        public int id_archivo { get; set; }
        public string nombre_archivo { get; set; } = "";
        public string descripcion { get; set; } = "";
        public string ruta_relativa { get; set; } = "";
        public string tipo_mime { get; set; } = "";
        public DateTime fecha_registro { get; set; }
    }

    public class AltaArchivoRequest
    {
        public string nombre_archivo { get; set; } = "";
        public string descripcion { get; set; } = "";
        public string ruta_relativa { get; set; } = "";
        public string tipo_mime { get; set; } = "";
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
    }

    public class LoginRequest
    {
        public string email { get; set; } = "";
        public string password { get; set; } = "";
    }

    public class LoginResponse
    {
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
        public string mensaje { get; set; } = "";
    }

    public static class Utils
    {
        public static string GetConnectionString()
        {
            string server = Environment.GetEnvironmentVariable("Server") ?? "";
            string database = Environment.GetEnvironmentVariable("Database") ?? "";
            string userId = Environment.GetEnvironmentVariable("UserID") ?? "";
            string password = Environment.GetEnvironmentVariable("Password") ?? "";

            return $"Server={server};Database={database};Uid={userId};Pwd={password};";
        }

        public static string GenerateToken()
        {
            var random = new byte[10];
            RandomNumberGenerator.Fill(random);
            return Convert.ToHexString(random);
        }
    }

    // Login del administrador
    public static class Login
    {
        [Function("login")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            FunctionContext log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                var loginRequest = JsonSerializer.Deserialize<LoginRequest>(requestBody);

                if (loginRequest == null || string.IsNullOrEmpty(loginRequest.email) || string.IsNullOrEmpty(loginRequest.password))
                    return new BadRequestObjectResult(new { mensaje = "Faltan campos" });

                using var connection = new MySqlConnection(Utils.GetConnectionString());
                await connection.OpenAsync();

                string query = "SELECT id_usuario, password FROM usuarios WHERE email = @e";
                using var command = new MySqlCommand(query, connection);
                command.Parameters.AddWithValue("@e", loginRequest.email);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    int idUsuario = reader.GetInt32("id_usuario");
                    string storedPassword = reader.GetString("password");

                    if (loginRequest.password == storedPassword)
                    {
                        string token = Utils.GenerateToken();
                        await reader.CloseAsync();

                        string updateQuery = "UPDATE usuarios SET token = @t WHERE id_usuario = @id";
                        using var updateCmd = new MySqlCommand(updateQuery, connection);
                        updateCmd.Parameters.AddWithValue("@t", token);
                        updateCmd.Parameters.AddWithValue("@id", idUsuario);
                        await updateCmd.ExecuteNonQueryAsync();

                        return new OkObjectResult(new LoginResponse
                        {
                            id_usuario = idUsuario,
                            token = token,
                            mensaje = "Login exitoso"
                        });
                    }
                }

                return new UnauthorizedObjectResult(new { mensaje = "Credenciales inválidas" });
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(new { mensaje = "Error interno: " + ex.Message });
            }
        }
    }

    // Consulta de archivos
    public static class GetArchivos
    {
        [Function("get_archivos")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            FunctionContext log)
        {
            try
            {
                using var connection = new MySqlConnection(Utils.GetConnectionString());
                await connection.OpenAsync();

                string query = "SELECT * FROM archivos ORDER BY fecha_registro DESC";
                using var command = new MySqlCommand(query, connection);

                using var reader = await command.ExecuteReaderAsync();
                var lista = new List<Archivo>();

                while (await reader.ReadAsync())
                {
                    lista.Add(new Archivo
                    {
                        id_archivo = reader.GetInt32("id_archivo"),
                        nombre_archivo = reader.GetString("nombre_archivo"),
                        descripcion = reader.GetString("descripcion"),
                        ruta_relativa = reader.GetString("ruta_relativa"),
                        tipo_mime = reader.GetString("tipo_mime"),
                        fecha_registro = reader.GetDateTime("fecha_registro")
                    });
                }

                return new OkObjectResult(lista);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(new { mensaje = "Error interno: " + ex.Message });
            }
        }
    }

    // Registro de nuevo archivo (admin)
    public static class UploadArchivo
    {
        [Function("upload_archivo")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            FunctionContext log)
        {
            try
            {
                string body = await new StreamReader(req.Body).ReadToEndAsync();
                var input = JsonSerializer.Deserialize<AltaArchivoRequest>(body);

                if (input == null || string.IsNullOrEmpty(input.nombre_archivo))
                    return new BadRequestObjectResult("Faltan campos obligatorios.");

                using var connection = new MySqlConnection(Utils.GetConnectionString());
                await connection.OpenAsync();

                // Validar token
                string validar = "SELECT COUNT(*) FROM usuarios WHERE id_usuario=@id AND token=@token";
                using var cmdVal = new MySqlCommand(validar, connection);
                cmdVal.Parameters.AddWithValue("@id", input.id_usuario);
                cmdVal.Parameters.AddWithValue("@token", input.token);

                long count = (long)(await cmdVal.ExecuteScalarAsync() ?? 0);
                if (count == 0)
                    return new UnauthorizedResult();

                string query = @"INSERT INTO archivos (nombre_archivo, descripcion, ruta_relativa, tipo_mime) 
                                 VALUES (@n, @d, @r, @t)";
                using var cmd = new MySqlCommand(query, connection);
                cmd.Parameters.AddWithValue("@n", input.nombre_archivo);
                cmd.Parameters.AddWithValue("@d", input.descripcion);
                cmd.Parameters.AddWithValue("@r", input.ruta_relativa);
                cmd.Parameters.AddWithValue("@t", input.tipo_mime);

                await cmd.ExecuteNonQueryAsync();

                return new OkObjectResult(new { mensaje = "Archivo registrado correctamente" });
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(new { mensaje = "Error interno: " + ex.Message });
            }
        }
    }
}
