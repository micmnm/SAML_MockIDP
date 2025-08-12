
using Microsoft.AspNetCore.Mvc;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Web;
using Microsoft.Extensions.Logging;

namespace TestSAML_MockIDP;

[ApiController]
[Route("saml2")]
public class SamlController : ControllerBase
{
    private readonly ILogger<SamlController> _logger;

    public SamlController(ILogger<SamlController> logger)
    {
        _logger = logger;
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

            // Mock user data
            var userEmail = "john.doe@example.com";
            var userName = "John Doe";
            
            _logger.LogInformation("Authenticated User Email: {UserEmail}", userEmail);
            _logger.LogInformation("Authenticated User Name: {UserName}", userName);

            // Generate SAML response
            var responseTime = DateTime.UtcNow;
            var samlResponse = GenerateSamlResponse(samlDoc, userEmail, userName, responseTime);
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

    private string GenerateSamlResponse(XmlDocument originalRequest, string userEmail, string userName, DateTime responseTime)
    {
        var namespaceManager = new XmlNamespaceManager(originalRequest.NameTable);
        namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        
        var authRequest = originalRequest.SelectSingleNode("//samlp:AuthnRequest", namespaceManager);
        var requestId = authRequest?.Attributes?["ID"]?.Value ?? Guid.NewGuid().ToString();
        
        var responseId = "_" + Guid.NewGuid().ToString();
        var assertionId = "_" + Guid.NewGuid().ToString();
        var issueInstant = responseTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        
        var samlResponse = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID=""{responseId}""
                Version=""2.0""
                IssueInstant=""{issueInstant}""
                Destination=""{ExtractAssertionConsumerServiceUrl(originalRequest)}""
                InResponseTo=""{requestId}"">
    <saml:Issuer>https://localhost:8888</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
    </samlp:Status>
    <saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
                    ID=""{assertionId}""
                    Version=""2.0""
                    IssueInstant=""{issueInstant}"">
        <saml:Issuer>https://localhost:8888</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"">{userEmail}</saml:NameID>
            <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
                <saml:SubjectConfirmationData NotOnOrAfter=""{responseTime.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}""
                                            Recipient=""{ExtractAssertionConsumerServiceUrl(originalRequest)}""
                                            InResponseTo=""{requestId}""/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore=""{responseTime.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}""
                        NotOnOrAfter=""{responseTime.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}"">
            <saml:AudienceRestriction>
                <saml:Audience>urn:example:sp</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant=""{issueInstant}"">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"">
                <saml:AttributeValue>{userEmail}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"">
                <saml:AttributeValue>{userName}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""ResponseGeneratedAt"">
                <saml:AttributeValue>{issueInstant}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>";

        return samlResponse;
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