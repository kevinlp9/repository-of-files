// Carlos Pineda G. 2025
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

    public class ConsultaArticulosRequest
    {
        public string palabra_clave { get; set; } = "";
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
    }

    public class Articulo
    {
        public int id_articulo { get; set; }
        public string nombre { get; set; } = "";
        public string descripcion { get; set; } = "";
        public decimal precio { get; set; }
        public int cantidad { get; set; }
        public string? fotografia { get; set; } // Base64 de la foto
    }

    public class AltaArticuloRequest
    {
        public Articulo articulo { get; set; } = new Articulo();
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
    }

    public class CompraArticuloRequest
    {
        public int id_articulo { get; set; }
        public int cantidad { get; set; }
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
    }

    public class EliminarCarritoRequest
    {
        public int id_usuario { get; set; }
        public string token { get; set; } = "";
    }

    public class ApiResponse
    {
        public string mensaje { get; set; } = "";
        public bool exito { get; set; }
    }

    // Función Login
    public static class Login
    {
        [Function("login")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                var loginRequest = JsonSerializer.Deserialize<LoginRequest>(requestBody);

                if (loginRequest == null || string.IsNullOrEmpty(loginRequest.email) || string.IsNullOrEmpty(loginRequest.password))
                {
                    return new BadRequestObjectResult(new { mensaje = "Email y contraseña son requeridos" });
                }

                string connectionString = Utils.GetConnectionString();

                using var connection = new MySqlConnection(connectionString);
                await connection.OpenAsync();

                // Verificar credenciales
                string query = "SELECT id_usuario, password FROM usuarios WHERE email = @email";
                using var command = new MySqlCommand(query, connection);
                command.Parameters.AddWithValue("@email", loginRequest.email);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    int idUsuario = reader.GetInt32("id_usuario");
                    string storedPassword = reader.IsDBNull("password") ? "" : reader.GetString("password");

                    // Verificar contraseña (comparación directa según tu esquema)
                    if (loginRequest.password == storedPassword)
                    {
                        string token = Utils.GenerateToken();

                        // Guardar token en base de datos (máximo 20 caracteres según tu esquema)
                        await reader.CloseAsync();
                        string updateQuery = "UPDATE usuarios SET token = @token WHERE id_usuario = @id";
                        using var updateCommand = new MySqlCommand(updateQuery, connection);
                        updateCommand.Parameters.AddWithValue("@token", token);
                        updateCommand.Parameters.AddWithValue("@id", idUsuario);
                        await updateCommand.ExecuteNonQueryAsync();

                        return new OkObjectResult(new LoginResponse
                        {
                            id_usuario = idUsuario,
                            token = token,
                            mensaje = "Login exitoso"
                        });
                    }
                }

                return new UnauthorizedObjectResult(new { mensaje = "Credenciales incorrectas" });
            }
            catch (Exception ex)
            {
                log.LogError($"Error en login: {ex.Message}");
                return new BadRequestObjectResult(new { mensaje = "Error interno del servidor" });
            }
        }
    }

    // Función Consulta Artículos
    public static class ConsultaArticulos
    {
        [Function("consulta_articulos")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                var consultaRequest = JsonSerializer.Deserialize<ConsultaArticulosRequest>(requestBody);

                if (consultaRequest == null || !await Utils.ValidateToken(consultaRequest.id_usuario, consultaRequest.token))
                {
                    return new UnauthorizedObjectResult(new { mensaje = "Token inválido" });
                }

                string connectionString = Utils.GetConnectionString();
                using var connection = new MySqlConnection(connectionString);
                await connection.OpenAsync();

                string query = @"
                    SELECT s.id_articulo, s.nombre, s.descripcion, s.precio, s.cantidad, 
                           fa.foto as fotografia
                    FROM stock s 
                    LEFT JOIN fotos_articulos fa ON s.id_articulo = fa.id_articulo
                    WHERE s.nombre LIKE @keyword OR s.descripcion LIKE @keyword";

                using var command = new MySqlCommand(query, connection);
                command.Parameters.AddWithValue("@keyword", $"%{consultaRequest.palabra_clave}%");

                var articulos = new List<Articulo>();
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    string? fotoBase64 = null;
                    if (!reader.IsDBNull("fotografia"))
                    {
                        byte[] fotoBytes = (byte[])reader["fotografia"];
                        fotoBase64 = Convert.ToBase64String(fotoBytes);
                    }

                    articulos.Add(new Articulo
                    {
                        id_articulo = reader.GetInt32("id_articulo"),
                        nombre = reader.GetString("nombre"),
                        descripcion = reader.IsDBNull("descripcion") ? "" : reader.GetString("descripcion"),
                        precio = reader.GetDecimal("precio"),
                        cantidad = reader.GetInt32("cantidad"),
                        fotografia = fotoBase64
                    });
                }

                return new OkObjectResult(articulos);
            }
            catch (Exception ex)
            {
                log.LogError($"Error en consulta_articulos: {ex.Message}");
                return new BadRequestObjectResult(new { mensaje = "Error al consultar artículos" });
            }
        }
    }

    // Función Alta Artículo
    public static class AltaArticulo
{
    [Function("alta_articulo")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
        ILogger log)
    {
        try
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var altaRequest = JsonSerializer.Deserialize<AltaArticuloRequest>(requestBody);

            if (altaRequest == null || !await Utils.ValidateToken(altaRequest.id_usuario, altaRequest.token))
            {
                return new UnauthorizedObjectResult(new { mensaje = "Token inválido" });
            }

            if (string.IsNullOrEmpty(altaRequest.articulo.nombre) || altaRequest.articulo.precio <= 0)
            {
                return new BadRequestObjectResult(new { mensaje = "Datos del artículo inválidos" });
            }

            string connectionString = Utils.GetConnectionString();
            using var connection = new MySqlConnection(connectionString);
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                // Insertar artículo en tabla stock
                string insertStockQuery = @"
                    INSERT INTO stock (nombre, descripcion, precio, cantidad) 
                    VALUES (@nombre, @descripcion, @precio, @cantidad);
                    SELECT LAST_INSERT_ID();";

                using var stockCommand = new MySqlCommand(insertStockQuery, connection, transaction);
                stockCommand.Parameters.AddWithValue("@nombre", altaRequest.articulo.nombre);
                stockCommand.Parameters.AddWithValue("@descripcion", altaRequest.articulo.descripcion ?? "");
                stockCommand.Parameters.AddWithValue("@precio", altaRequest.articulo.precio);
                stockCommand.Parameters.AddWithValue("@cantidad", altaRequest.articulo.cantidad);

                var idArticulo = await stockCommand.ExecuteScalarAsync();
                int articuloId = Convert.ToInt32(idArticulo);

                // Si hay foto, insertarla en fotos_articulos
                if (!string.IsNullOrEmpty(altaRequest.articulo.fotografia))
                {
                    byte[] fotoBytes = Convert.FromBase64String(altaRequest.articulo.fotografia);

                    string insertFotoQuery = @"
                        INSERT INTO fotos_articulos (foto, id_articulo) 
                        VALUES (@foto, @id_articulo)";

                    using var fotoCommand = new MySqlCommand(insertFotoQuery, connection, transaction);
                    fotoCommand.Parameters.AddWithValue("@foto", fotoBytes);
                    fotoCommand.Parameters.AddWithValue("@id_articulo", articuloId);
                    await fotoCommand.ExecuteNonQueryAsync();
                }

                await transaction.CommitAsync();
                return new OkObjectResult(new ApiResponse
                {
                    mensaje = "Artículo agregado exitosamente",
                    exito = true
                });
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                log.LogError($"Error en transacción: {ex.Message}");
                return new BadRequestObjectResult(new { mensaje = "Error al agregar artículo" });
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error en alta_articulo: {ex.Message}");
            return new BadRequestObjectResult(new { mensaje = "Error al agregar artículo" });
        }
    }
}


    // Función Compra Artículo
    public static class CompraArticulo
    {
        [Function("compra_articulo")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                var compraRequest = JsonSerializer.Deserialize<CompraArticuloRequest>(requestBody);

                if (compraRequest == null || !await Utils.ValidateToken(compraRequest.id_usuario, compraRequest.token))
                {
                    return new UnauthorizedObjectResult(new { mensaje = "Token inválido" });
                }

                string connectionString = Utils.GetConnectionString();
                using var connection = new MySqlConnection(connectionString);
                await connection.OpenAsync();

                // Verificar disponibilidad del artículo
                string checkQuery = "SELECT cantidad FROM stock WHERE id_articulo = @id_articulo";
                using var checkCommand = new MySqlCommand(checkQuery, connection);
                checkCommand.Parameters.AddWithValue("@id_articulo", compraRequest.id_articulo);

                var result = await checkCommand.ExecuteScalarAsync();
                if (result == null)
                {
                    return new BadRequestObjectResult(new { mensaje = "Artículo no encontrado" });
                }

                int disponible = Convert.ToInt32(result);
                if (disponible < compraRequest.cantidad)
                {
                    return new BadRequestObjectResult(new { mensaje = "Cantidad no disponible" });
                }

                // Agregar al carrito (usando el nombre correcto de la tabla)
                string insertQuery = @"
                    INSERT INTO carrito_compra (id_usuario, id_articulo, cantidad) 
                    VALUES (@id_usuario, @id_articulo, @cantidad)
                    ON DUPLICATE KEY UPDATE cantidad = cantidad + @cantidad";

                using var insertCommand = new MySqlCommand(insertQuery, connection);
                insertCommand.Parameters.AddWithValue("@id_usuario", compraRequest.id_usuario);
                insertCommand.Parameters.AddWithValue("@id_articulo", compraRequest.id_articulo);
                insertCommand.Parameters.AddWithValue("@cantidad", compraRequest.cantidad);

                int rowsAffected = await insertCommand.ExecuteNonQueryAsync();

                if (rowsAffected > 0)
                {
                    return new OkObjectResult(new ApiResponse
                    {
                        mensaje = "Artículo agregado al carrito",
                        exito = true
                    });
                }

                return new BadRequestObjectResult(new { mensaje = "Error al agregar al carrito" });
            }
            catch (Exception ex)
            {
                log.LogError($"Error en compra_articulo: {ex.Message}");
                return new BadRequestObjectResult(new { mensaje = "Error al procesar compra" });
            }
        }
    }

    // Función Eliminar Carrito
    public static class EliminaCarritoCompra
    {
        [Function("elimina_carrito_compra")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req,
            ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                var eliminarRequest = JsonSerializer.Deserialize<EliminarCarritoRequest>(requestBody);

                if (eliminarRequest == null || !await Utils.ValidateToken(eliminarRequest.id_usuario, eliminarRequest.token))
                {
                    return new UnauthorizedObjectResult(new { mensaje = "Token inválido" });
                }

                string connectionString = Utils.GetConnectionString();
                using var connection = new MySqlConnection(connectionString);
                await connection.OpenAsync();

                string query = "DELETE FROM carrito_compra WHERE id_usuario = @id_usuario";
                using var command = new MySqlCommand(query, connection);
                command.Parameters.AddWithValue("@id_usuario", eliminarRequest.id_usuario);

                int rowsAffected = await command.ExecuteNonQueryAsync();

                return new OkObjectResult(new ApiResponse
                {
                    mensaje = $"Carrito vaciado. {rowsAffected} elementos eliminados.",
                    exito = true
                });
            }
            catch (Exception ex)
            {
                log.LogError($"Error en elimina_carrito_compra: {ex.Message}");
                return new BadRequestObjectResult(new { mensaje = "Error al vaciar carrito" });
            }
        }
    }

    // Funciones auxiliares
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

        public static async Task<bool> ValidateToken(int idUsuario, string token)
        {
            try
            {
                string connectionString = GetConnectionString();
                using var connection = new MySqlConnection(connectionString);
                await connection.OpenAsync();

                string query = "SELECT token FROM usuarios WHERE id_usuario = @id AND token = @token";
                using var command = new MySqlCommand(query, connection);
                command.Parameters.AddWithValue("@id", idUsuario);
                command.Parameters.AddWithValue("@token", token);

                var result = await command.ExecuteScalarAsync();
                return result != null && result.ToString() == token;
            }
            catch
            {
                return false;
            }
        }

        public static string GenerateToken()
        {
            // Generar token aleatorio de 20 caracteres (límite de tu BD)
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 20)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static bool VerifyPassword(string password, string storedPassword)
        {
            // Tu esquema almacena contraseñas en texto plano (máximo 20 caracteres)
            // En producción considera usar hashing para mayor seguridad
            return password == storedPassword;
        }
    }


}