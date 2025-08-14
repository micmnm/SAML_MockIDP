using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Web;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace TestSAML_MockIDP;

[ApiController]
[Route("saml2")]
public class SamlController : ControllerBase
{
    private readonly ILogger<SamlController> _logger;
    private readonly IConfiguration _configuration;
    private string _idpBaseUrl;

    public SamlController(ILogger<SamlController> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        _idpBaseUrl = "https://localhost:8888";
    }

    // Property to get the IDP Entity ID based on the current request
    private string IdpEntityId => $"{_idpBaseUrl}/saml2/metadata";

    [HttpGet("metadata")]
    public async Task<IActionResult> GetMetadata()
    {
        var metadata = GenerateSamlMetadata();
        
        Response.Headers.Add("Content-Disposition", "inline; filename=metadata.xml");
        return Content(metadata, "application/samlmetadata+xml");
    }

    [HttpGet("sso/web")]
    public async Task<IActionResult> SingleSignOn([FromQuery] string SAMLRequest, [FromQuery] string RelayState = null)
    {
        var requestTime = DateTime.UtcNow;
        var requestId = string.Empty;
        
        try
        {
            _logger.LogInformation("=== SAML SSO REQUEST RECEIVED ===");
            _logger.LogInformation("Request Time: {RequestTime:yyyy-MM-dd HH:mm:ss.fff} UTC", requestTime);
            _logger.LogInformation("RelayState: {RelayState}", RelayState ?? "(null)");

            if (string.IsNullOrEmpty(SAMLRequest))
            {
                _logger.LogError("SAMLRequest parameter is missing");
                return BadRequest("SAMLRequest parameter is required");
            }

            // Decode and parse the SAML request
            var decodedRequest = DecodeSamlRequest(SAMLRequest);
            var samlDoc = new XmlDocument();
            samlDoc.LoadXml(decodedRequest);

            // Extract Request ID and log it
            requestId = ExtractSamlRequestId(samlDoc);
            _logger.LogInformation("SAML Request ID: {RequestId}", requestId);
            _logger.LogInformation("Decoded SAML Request: {DecodedRequest}", decodedRequest);

            // Extract AssertionConsumerServiceURL from the SAML request
            var assertionConsumerServiceUrl = ExtractAssertionConsumerServiceUrl(samlDoc);
            _logger.LogInformation("AssertionConsumerServiceURL: {AcsUrl}", assertionConsumerServiceUrl);
            
            if (string.IsNullOrEmpty(assertionConsumerServiceUrl))
            {
                _logger.LogError("AssertionConsumerServiceURL not found in SAML request");
                return BadRequest("AssertionConsumerServiceURL not found in SAML request");
            }

            // Extract EntityID from the SAML request
            var entityId = ExtractEntityId(samlDoc);
            _logger.LogInformation("Service Provider EntityID: {EntityId}", entityId);

            // Mock user data
            var userEmail = "john.doe@example.com";
            var userName = "John Doe";
            
            _logger.LogInformation("Authenticated User Email: {UserEmail}", userEmail);
            _logger.LogInformation("Authenticated User Name: {UserName}", userName);

            // Generate SAML response
            var responseTime = DateTime.UtcNow;
            var samlResponse = GenerateSamlResponse(samlDoc, userEmail, userName, responseTime, entityId);
            var encodedResponse = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponse));

            _logger.LogInformation("=== SAML SSO RESPONSE GENERATED ===");
            _logger.LogInformation("Response Time: {ResponseTime:yyyy-MM-dd HH:mm:ss.fff} UTC", responseTime);
            _logger.LogInformation("Processing Duration: {Duration}ms", (responseTime - requestTime).TotalMilliseconds);
            _logger.LogInformation("Generated SAML Response: {SamlResponse}", samlResponse);

            // Create HTML form for auto-posting to ACS URL
            var htmlForm = CreateAutoPostForm(assertionConsumerServiceUrl, encodedResponse, RelayState, userEmail, responseTime);

            return Content(htmlForm, "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML request. RequestId: {RequestId}, RequestTime: {RequestTime}", 
                requestId, requestTime);
            return BadRequest($"Error processing SAML request: {ex.Message}");
        }
    }

    private string DecodeSamlRequest(string samlRequest)
    {
        try
        {
            // SAML requests are typically base64 encoded and deflated
            var decodedBytes = Convert.FromBase64String(samlRequest);
            
            using var compressedStream = new MemoryStream(decodedBytes);
            using var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress);
            using var resultStream = new MemoryStream();
            
            deflateStream.CopyTo(resultStream);
            return Encoding.UTF8.GetString(resultStream.ToArray());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decode SAML request");
            throw;
        }
    }

    private string ExtractSamlRequestId(XmlDocument samlDoc)
    {
        try
        {
            var namespaceManager = new XmlNamespaceManager(samlDoc.NameTable);
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            
            var authRequest = samlDoc.SelectSingleNode("//samlp:AuthnRequest", namespaceManager);
            return authRequest?.Attributes?["ID"]?.Value ?? "Unknown";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract SAML Request ID");
            return "Unknown";
        }
    }

    private string ExtractAssertionConsumerServiceUrl(XmlDocument samlDoc)
    {
        var namespaceManager = new XmlNamespaceManager(samlDoc.NameTable);
        namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        
        var authRequest = samlDoc.SelectSingleNode("//samlp:AuthnRequest", namespaceManager);
        return authRequest?.Attributes?["AssertionConsumerServiceURL"]?.Value;
    }

    private string ExtractEntityId(XmlDocument samlDoc)
    {
        try
        {
            var namespaceManager = new XmlNamespaceManager(samlDoc.NameTable);
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            
            // Try to extract from AuthnRequest Issuer
            var issuerNode = samlDoc.SelectSingleNode("//saml:Issuer", namespaceManager);
            var entityId = issuerNode?.InnerText;
            
            if (string.IsNullOrEmpty(entityId))
            {
                // Fallback: try to get from AuthnRequest attributes
                var authRequest = samlDoc.SelectSingleNode("//samlp:AuthnRequest", namespaceManager);
                entityId = authRequest?.Attributes?["Issuer"]?.Value;
            }
            
            return entityId ?? "urn:example:sp";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract EntityID from SAML request");
            return "urn:example:sp";
        }
    }

    private string GenerateSamlResponse(XmlDocument originalRequest, string userEmail, string userName, DateTime responseTime, string spEntityId)
    {
        var namespaceManager = new XmlNamespaceManager(originalRequest.NameTable);
        namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        var authRequest = originalRequest.SelectSingleNode("//samlp:AuthnRequest", namespaceManager);
        var requestId = authRequest?.Attributes?["ID"]?.Value ?? Guid.NewGuid().ToString();
        
        var responseId = "_" + Guid.NewGuid().ToString();
        var assertionId = "_" + Guid.NewGuid().ToString();
        var issueInstant = responseTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var notBefore = responseTime.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var notOnOrAfter = responseTime.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

        var samlResponseXml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                 xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                 ID=""{responseId}""
                 Version=""2.0""
                 IssueInstant=""{issueInstant}""
                Destination=""{ExtractAssertionConsumerServiceUrl(originalRequest)}""
                InResponseTo=""{requestId}"">
    <saml2:Issuer>{IdpEntityId}</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                     ID=""{assertionId}""
                     Version=""2.0""
                     IssueInstant=""{issueInstant}"">
        <saml2:Issuer>{IdpEntityId}</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"">{userEmail}</saml2:NameID>
            <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
                <saml2:SubjectConfirmationData NotOnOrAfter=""{responseTime.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}""
                                            Recipient=""{ExtractAssertionConsumerServiceUrl(originalRequest)}""
                                            InResponseTo=""{requestId}""/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore=""{notBefore}"" NotOnOrAfter=""{notOnOrAfter}"">
            <saml2:AudienceRestriction>
                <saml2:Audience>{spEntityId}</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant=""{issueInstant}"">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"">
                <saml2:AttributeValue>{userEmail}</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"">
                <saml2:AttributeValue>{userName}</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>";

        var doc = new XmlDocument();
        doc.LoadXml(samlResponseXml);

        // Sign the SAML response
        SignSamlDocument(doc);

        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    private void SignSamlDocument(XmlDocument doc)
    {
        try
        {
            // Get certificate paths from configuration
            var publicCertPath = _configuration["Saml:PublicCertificate"];
            var privateCertPath = _configuration["Saml:PrivateCertificate"];

            if (string.IsNullOrEmpty(publicCertPath) || string.IsNullOrEmpty(privateCertPath))
            {
                _logger.LogWarning("SAML certificate paths not configured. Response will not be signed.");
                return;
            }

            // Load the certificate
            var cert = LoadCertificateFromFiles(publicCertPath, privateCertPath);
            
            if (cert == null)
            {
                _logger.LogWarning("Failed to load SAML certificates. Response will not be signed.");
                return;
            }

            // Create the signed XML
            var signedXml = new SignedXml(doc);
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            // Create a reference to be signed
            var reference = new Reference();
            reference.Uri = "";
            
            // Add an enveloped transformation to the reference
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            
            signedXml.AddReference(reference);

            // Add the key info
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;

            // Compute the signature
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save it to an XmlElement object
            var xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign SAML response");
            // Continue without signing rather than failing completely
        }
    }

    private X509Certificate2 LoadCertificateFromFiles(string publicCertPath, string privateCertPath)
    {
        try
        {
            // Load public certificate
            var publicCertBytes = System.IO.File.ReadAllBytes(publicCertPath);
            var publicCert = new X509Certificate2(publicCertBytes);

            // Load private key
            var privateKeyPem = System.IO.File.ReadAllText(privateCertPath);
            
            // Parse the private key (assuming PEM format)
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);

            // Combine public certificate with private key
            var certWithKey = publicCert.CopyWithPrivateKey(rsa);
            
            return certWithKey;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificates from files: {PublicCert}, {PrivateCert}", 
                publicCertPath, privateCertPath);
            return null;
        }
    }

    private string GenerateSamlMetadata()
    {
        var validUntil = DateTime.UtcNow.AddYears(10).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        
        var metadata = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata""
                     xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""
                     entityID=""{IdpEntityId}""
                     validUntil=""{validUntil}"">
    <md:IDPSSODescriptor WantAuthnRequestsSigned=""false""
                         protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
        <md:KeyDescriptor use=""signing"">
            <ds:KeyInfo>
                <ds:KeyName>MockIDP-Signing-Key</ds:KeyName>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
                               Location=""{_idpBaseUrl}/saml2/sso/web""/>
        <md:SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
                               Location=""{_idpBaseUrl}/saml2/sso/web""/>
        <md:AttributeService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:SOAP""
                            Location=""{_idpBaseUrl}/saml2/attribute""/>
    </md:IDPSSODescriptor>
    <md:ContactPerson contactType=""technical"">
        <md:GivenName>Mock IDP</md:GivenName>
        <md:EmailAddress>admin@mockidp.local</md:EmailAddress>
    </md:ContactPerson>
    <md:ContactPerson contactType=""support"">
        <md:GivenName>Mock IDP Support</md:GivenName>
        <md:EmailAddress>support@mockidp.local</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>";

    // Sign the metadata document
    var doc = new XmlDocument();
    doc.LoadXml(metadata);
    SignSamlDocument(doc);
    
    return doc.OuterXml;
}

    private string CreateAutoPostForm(string actionUrl, string samlResponse, string relayState, string userEmail, DateTime responseTime)
    {
        var relayStateInput = !string.IsNullOrEmpty(relayState) 
            ? $@"<input type=""hidden"" name=""RelayState"" value=""{HttpUtility.HtmlEncode(relayState)}"" />"
            : "";
        
         var samlBytes = Encoding.UTF8.GetBytes(samlResponse);
         using (var output = new MemoryStream())
         {
             using var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true);
             deflate.Write(samlBytes, 0, samlBytes.Length);
             deflate.Close();
             samlResponse = Convert.ToBase64String(output.ToArray());
         }
        

        return $@"<!DOCTYPE html>
<html>
<head>
    <title>SAML Response - Mock IDP</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .info {{ background: #f0f8ff; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .highlight {{ color: #0066cc; font-weight: bold; }}
    </style>
</head>
<body onload=""setTimeout(function(){{   document.forms[0].submit();    }}, 60000)"">
    <div class=""info"">
        <h3>Mock SAML IDP - SSO Response</h3>
        <p><strong>IDP Entity ID:</strong> <span class=""highlight"">{IdpEntityId}</span></p>
        <p><strong>Response Time:</strong> <span class=""highlight"">{responseTime:yyyy-MM-dd HH:mm:ss.fff} UTC</span></p>
        <p><strong>Authenticated User:</strong> <span class=""highlight"">{HttpUtility.HtmlEncode(userEmail)}</span></p>
        <p><strong>Redirecting to:</strong> {HttpUtility.HtmlEncode(actionUrl)}</p>
        <p><em>Form will auto-submit in a moment...</em></p>
    </div>
    
    <form method=""post"" action=""{HttpUtility.HtmlEncode(actionUrl)}"">
        <input type=""text"" name=""SAMLResponse"" value=""{HttpUtility.HtmlEncode(samlResponse)}"" />
        {relayStateInput}
        <!--noscript-->
            <input type=""submit"" value=""Continue to Service Provider"" />
        <!--/noscript-->
    </form>
</body>
</html>";
    }
}