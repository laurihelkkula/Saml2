using System;
using System.Security.Cryptography;
using System.Xml;
using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2.AesGcmExtension
{
  public static class AesGcmRegistration
  {
    /// <summary>
    /// Applies support for http://www.w3.org/2009/xmlenc11#aes128-gcm in SamlResponses
    /// </summary>
    public static void RegisterAesGcmSupport()
    {
      RegisterAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm128Identifier);
      RegisterRSAEncryptedXmlFactory((document, rsa) => new AesGcmRsaEncryptedXml(document, rsa));
    }

    /// <summary>
    /// Registers a custom RSAEncryptedXmlFactory
    /// </summary>
    public static void RegisterRSAEncryptedXmlFactory(Func<XmlDocument, RSA, RSAEncryptedXml> creator)
    {
      RSAEncryptedXmlFactory.Creator = creator;
    }

    /// <summary>
    /// Registers a crypto algorithm
    /// </summary>
    /// <param name="algorithmImplementation">Implementation class type</param>
    /// <param name="identifier">Algorithm identifier</param>
    public static void RegisterAlgorithm(Type algorithmImplementation, string identifier)
    {
      CryptoConfig.AddAlgorithm(algorithmImplementation, identifier);
    }
  }
}
