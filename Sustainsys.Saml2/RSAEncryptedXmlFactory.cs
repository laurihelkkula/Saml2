using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2
{
  public static class RSAEncryptedXmlFactory
  {
    /// <summary>
    /// Use the setter to use a custom RSAEncryptedXml implementation.
    /// RSAEncryptedXml is only use for decrypting SAML messages
    /// </summary>
    public static Func<XmlDocument, RSA, RSAEncryptedXml> Creator { get; set; } =
      (document, rsaKey) => new RSAEncryptedXml(document, rsaKey);

    public static RSAEncryptedXml Create(XmlDocument document, RSA rsaKey)
    {
      return Creator(document, rsaKey);
    }
  }
}
