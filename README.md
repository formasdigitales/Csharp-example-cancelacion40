# Csharp-example-Cancelacion40

Ejemplo de cancelación C#

### Requerimientos

.Net 6.0

### Estructura de proyecto
- Directorio Raiz
  - Program.cs
  - Procesaxml.cs
- Directorio resource
  - CSD_Sucursal_1_EKU9003173C9_20230517_223850.cer //  archivo certificado publico
  - CSD_Sucursal_1_EKU9003173C9_20230517_223850.key // archivo llave privada
- Directorio Connected Services
  - Directorio ServiceCancelacionWS // servicio cliente SOAP

### Ejemplo del metodo Cancelacion  1

```C#

String pathcert = "C://resource/CSD_Sucursal_1_EKU9003173C9_20230517_223850.cer"; //Path del certificado publico del CSD
        String pathKey  = "C://resource/CSD_Sucursal_1_EKU9003173C9_20230517_223850.key"; // Path de la llave privada del CSD
 
        String passkey = "12345678a"; // Contraseña del CSD
        String RFC_EMISOR = "EKU9003173C9"; // rfc del emisor
        String UUIDToCancel = "68F61FED-B7BB-4928-BC85-D69BFB3BB963"; // UUID a cancelar
        String fecha = "2023-11-15T12:03:57"; // fecha de timbrado
 
        public void Cancelacion40_1()
        {
            wsFolio folio = new wsFolio();
            folio.uuid = UUIDToCancel;
            folio.motivo = "02";

            // creas array de folios a cancelar
            wsFolios40[] folios40 = { new wsFolios40 { folio = folio } };

            // lees certificado publico del CSD y la llave privada del CSD
            var certificateBytes = File.ReadAllBytes(pathcert);
            var privateKeyBytes = File.ReadAllBytes(pathKey);

            // credenciales del cliente SOAP 
            accesos accesos = new accesos { usuario = "pruebasWS", password = "pruebasWS"};

            WSCancelacion40 wSCancelacion40 = new WSCancelacion40Client();
            Cancelacion40_1Request request = new Cancelacion40_1Request();
            request.rfcEmisor = RFC_EMISOR;
            request.accesos = accesos;
            request.fecha = fecha;
            request.folios = folios40;
            request.password = passkey;
            request.publicKey = certificateBytes;
            request.privateKey = privateKeyBytes;

            // Descomentar para ver el XML a enviar al servicio SOAP
            /*   XmlSerializer serializer = new XmlSerializer(typeof(Cancelacion40_1Request));

               using (StringWriter writer = new StringWriter())
               {
                   serializer.Serialize(writer, request);                
                   Console.WriteLine(writer.ToString());
               }    */

            Task<Cancelacion40_1Response> response = wSCancelacion40.Cancelacion40_1Async(request);

            Console.WriteLine("Codigo Status " + response.Result.@return.codEstatus);
            Console.WriteLine("Mensaje " + response.Result.@return.mensaje);

        }

```
