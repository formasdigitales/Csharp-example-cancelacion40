using System.Xml;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using ServiceCancelacionWS;
using System.Xml.Linq;
using JavaScience;
using System.Xml.Serialization;
using System.Numerics;
using System;
using System.Text;
using Org.BouncyCastle.Crypto;
 using System.Threading.Tasks;
using System.IO;
using ServiceCancelacionWS;

namespace Csharp_example_cancelacion40
{
    class Procesaxml
    {
        
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


        public void Cancelacion40_2()
        {
            wsFolio folio = new wsFolio();
            folio.uuid = UUIDToCancel;
            folio.motivo = "02";

            wsFolios40[] folios40 = { new wsFolios40 { folio = folio } };

            var certificateBytes = File.ReadAllBytes(pathcert);
            var privateKeyBytes = File.ReadAllBytes(pathKey);

            SignatureType signatureType = GetCancellationSignatureType(RFC_EMISOR, fecha, folios40, certificateBytes, privateKeyBytes, passkey);

            accesos accesos = new accesos { usuario = "pruebasWS", password = "pruebasWS" };

            WSCancelacion40 wSCancelacion40 = new WSCancelacion40Client();
            Cancelacion40_2Request request = new Cancelacion40_2Request();
            request.rfcEmisor = RFC_EMISOR;
            request.accesos = accesos;
            request.fecha = fecha;
            request.folios = folios40;
            request.signatureType = signatureType;


            // Descomentar para ver el XML a enviar
            XmlSerializer serializer = new XmlSerializer(typeof(Cancelacion40_2Request));

            using (StringWriter writer = new StringWriter())
            {
                serializer.Serialize(writer, request);
                Console.WriteLine("******************************** Request ********************************");
                Console.WriteLine(writer.ToString());
            }

            Task<Cancelacion40_2Response> response = wSCancelacion40.Cancelacion40_2Async(request);

            Console.WriteLine("Codigo Status " + response.Result.@return.codEstatus);
            Console.WriteLine("Codigo Status " + response.Result.@return.mensaje);

        }

        private SignatureType GetCancellationSignatureType(string rfcEmisor, string cancellationDate, wsFolios40[] folios, byte[] certificateBytes, byte[] privateKeyBytes, string privateKeyPassword)
        {
            try
            {
                X509Certificate2 certificate = new X509Certificate2(certificateBytes);

                // Access the SerialNumber property as a byte array
                byte[] serialNumberBytes = certificate.GetSerialNumber();

                // Convert the byte array to a hexadecimal string for comparison
                string serialNumberDecimal = new BigInteger(serialNumberBytes.Concat(new byte[] { 0 }).ToArray()).ToString();

                SecureString passSecure = new SecureString();
                passSecure.Clear();
                foreach (char c in privateKeyPassword.ToCharArray())
                {
                    passSecure.AppendChar(c);
                }

                RSACryptoServiceProvider rsaCryptoServiceProvider = opensslkey.DecodeEncryptedPrivateKeyInfo(privateKeyBytes, passSecure);
                RSAParameters rsaParameters = rsaCryptoServiceProvider.ExportParameters(true);

                // Crea una nueva instancia de RSA y la importa con los parámetros
                RSA privateKey = RSA.Create();
                privateKey.ImportParameters(rsaParameters);

                string cancellationXml = GetSerializedCancellation(rfcEmisor, cancellationDate, folios);
                Console.WriteLine(cancellationXml);

                //   string cancellationXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><Cancelacion xmlns=\"http://cancelacfd.sat.gob.mx\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Fecha=\"2023-11-15T12:03:57\" RfcEmisor=\"EKU9003173C9\"><Folios><Folio FolioSustitucion=\"\" Motivo=\"02\" UUID=\"68F61FED-B7BB-4928-BC85-D69BFB3BB963\"/></Folios></Cancelacion>";

                var  xmlSignature = GetXmlSignature(cancellationXml, certificate, privateKey);

                var reference = (Reference)xmlSignature.SignedInfo.References[0];

                SignatureType signatureType = new SignatureType();
                SignedInfoType signedInfoType = new SignedInfoType();
                CanonicalizationMethodType canonicalizationMethodType = new CanonicalizationMethodType();
                canonicalizationMethodType.Algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
                signedInfoType.CanonicalizationMethod = canonicalizationMethodType;
                SignatureMethodType signatureMethodType = new SignatureMethodType();
                signatureMethodType.Algorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
                signedInfoType.SignatureMethod = signatureMethodType;

                ReferenceType referenceType = new ReferenceType();
                referenceType.URI = "";

                TransformType transformType = new TransformType();
                transformType.Algorithm = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
                TransformType[] arrayOfTransformType = { transformType };
                referenceType.Transforms = arrayOfTransformType;

                DigestMethodType digestMethodType = new DigestMethodType();
                digestMethodType.Algorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

                referenceType.DigestMethod = digestMethodType;
                referenceType.DigestValue = reference.DigestValue;

                ReferenceType[] referenceTypeList = { referenceType };
                signedInfoType.Reference = referenceTypeList;
                signatureType.SignedInfo = signedInfoType;

                SignatureValueType signatureValueType = new SignatureValueType();
                // signatureValueType.Id = xmlSignature.SignatureValueId;

                signatureValueType.Value = xmlSignature.SignatureValue;
                signatureType.SignatureValue = signatureValueType;

                KeyInfoType keyInfoType = new KeyInfoType();
                X509DataType x509DataType = new X509DataType();
                X509IssuerSerialType x509IssuerSerialType = new X509IssuerSerialType();
                x509IssuerSerialType.X509IssuerName = certificate.Issuer;
                x509IssuerSerialType.X509SerialNumber = serialNumberDecimal;

                x509DataType.Items = new object[] { x509IssuerSerialType, certificate.RawData };

                keyInfoType.Items = new object[] { x509DataType };
                ItemsChoiceType1[] itemsElementName1 = { ItemsChoiceType1.X509IssuerSerial, ItemsChoiceType1.X509Certificate };
                x509DataType.ItemsElementName = itemsElementName1;


                ItemsChoiceType2[] itemsElementName2 = { ItemsChoiceType2.X509Data };
                keyInfoType.ItemsElementName = itemsElementName2;

                signatureType.KeyInfo = keyInfoType;
                return signatureType;
            }
            catch (Exception ex)
            {
                throw new Exception("ERROR_SIGNING_CANCELLATION", ex);
            }
        }


        public string GetSerializedCancellation(string rfcEmisor, string cancellationDate, wsFolios40[] folios)
        {
            XDocument document = new XDocument();
            XDeclaration declaration = new XDeclaration("1.0", "UTF-8", "no");
            document.Declaration = declaration;

            XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
            XNamespace xsd = "http://www.w3.org/2001/XMLSchema";
            XNamespace xmlns = "http://cancelacfd.sat.gob.mx";

            XElement cancelacion = new XElement(xmlns + "Cancelacion");

            cancelacion.SetAttributeValue("xmlns", xmlns);
            cancelacion.SetAttributeValue(XNamespace.Xmlns + "xsd", xsd);
            cancelacion.SetAttributeValue(XNamespace.Xmlns + "xsi", xsi);

            cancelacion.SetAttributeValue("Fecha", cancellationDate);
            cancelacion.SetAttributeValue("RfcEmisor", rfcEmisor);


            for (int i = 0; i < folios.Length; i++)
            {
                XElement foliosElement = new XElement(xmlns + "Folios");
                XElement folioElement = new XElement(xmlns + "Folio");

                folioElement.SetAttributeValue("FolioSustitucion", "");
                folioElement.SetAttributeValue("Motivo", folios[i].folio.motivo);
                folioElement.SetAttributeValue("UUID", folios[i].folio.uuid);


                foliosElement.Add(folioElement);
                cancelacion.Add(foliosElement);
            }

            document.Add(cancelacion);

            var sb = new StringBuilder();
            var sw = new StringWriterUtf8(sb);
            document.Save(sw);

            return sw.ToString();
        }


        private SignedXml GetXmlSignature(string xml, X509Certificate2 x509Certificate, RSA privateKey)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(xml);

            var signedXml = new SignedXml(document);

            var reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            // Create the SignedInfo.
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(x509Certificate));

            signedXml.KeyInfo = keyInfo;
            signedXml.SigningKey = privateKey;

            signedXml.ComputeSignature();

            // Add the signature element to the XML document.
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            document.DocumentElement.AppendChild(document.ImportNode(xmlDigitalSignature, true));

            return signedXml;
        }

        private SignedXml GetXmlSignature2(string xml, X509Certificate2 x509Certificate, RSA privateKey)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;

            // Asegurar que el contenido XML se cargue con la codificación UTF-8
            byte[] xmlBytes = Encoding.UTF8.GetBytes(xml);
            using (MemoryStream stream = new MemoryStream(xmlBytes))
            {
                XmlReaderSettings settings = new XmlReaderSettings();
                settings.DtdProcessing = DtdProcessing.Parse;
                using (XmlReader reader = XmlReader.Create(stream, settings))
                {
                    document.Load(reader);
                }
            }

            var signedXml = new SignedXml(document);

            Reference reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            // Crear el SignedInfo.
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(x509Certificate));

            signedXml.KeyInfo = keyInfo;
            signedXml.SigningKey = privateKey;

            signedXml.ComputeSignature();

            // Agregar el elemento de firma al documento XML.
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            document.DocumentElement.AppendChild(document.ImportNode(xmlDigitalSignature, true));

            return signedXml;
        }


        public class StringWriterUtf8 : StringWriter
        {
            public StringWriterUtf8(StringBuilder sb) : base(sb)
            {
            }

            public override Encoding Encoding
            {
                get { return Encoding.UTF8; }
            }
        }

    }
}
