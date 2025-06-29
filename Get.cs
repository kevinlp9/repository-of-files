
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using System.Web;

namespace t8vs2022630077
{
    public static class Get
    {
        [Function("Get")]
        public static IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")]
            HttpRequest req)
        {
            try
            {
                // Obtener parámetros de la URL
                string? path = req.Query["nombre"];
                bool descargar = req.Query["descargar"] == "si";
                string? root = Environment.GetEnvironmentVariable("ROOT");

                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root))
                    return new BadRequestObjectResult("Parámetros inválidos.");

                // Asegurarse de que la ruta esté dentro del directorio ROOT
                string ruta_completa = Path.GetFullPath(root + path);
                if (!ruta_completa.StartsWith(root))
                    return new BadRequestObjectResult("Ruta fuera del directorio raíz.");

                // Leer archivo solicitado
                byte[] contenido;
                try
                {
                    contenido = File.ReadAllBytes(ruta_completa);
                }
                catch (FileNotFoundException)
                {
                    return new NotFoundResult();
                }

                // Obtener el nombre del archivo
                string? nombre = Path.GetFileName(path);
                if (string.IsNullOrEmpty(nombre))
                    return new BadRequestObjectResult("Nombre de archivo inválido.");

                // Determinar tipo MIME
                string tipo_mime = MimeMapping.GetMimeMapping(nombre!);

                // Fecha de última modificación
                DateTime fecha_modificacion = File.GetLastWriteTimeUtc(ruta_completa);

                // Manejo de caché: If-Modified-Since
                string? fecha_header = req.Headers["If-Modified-Since"];
                if (!string.IsNullOrEmpty(fecha_header))
                {
                    if (DateTime.TryParse(fecha_header, out DateTime fecha_cliente))
                    {
                        fecha_cliente = fecha_cliente.ToUniversalTime();
                        if (fecha_cliente == fecha_modificacion)
                            return new StatusCodeResult(304); // Not Modified
                    }
                }

                // Responder archivo: descarga o carga en navegador
                if (descargar)
                {
                    return new FileContentResult(contenido, tipo_mime)
                    {
                        FileDownloadName = nombre
                    };
                }
                else
                {
                    return new FileContentResult(contenido, tipo_mime)
                    {
                        LastModified = fecha_modificacion
                    };
                }
            }
            catch (Exception e)
            {
                return new BadRequestObjectResult($"Error: {e.Message}");
            }
        }
    }
}
