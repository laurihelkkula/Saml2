using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2.AesGcmExtension
{
  internal class AesGcmRsaEncryptedXml : RSAEncryptedXml
  {
    public AesGcmRsaEncryptedXml(XmlDocument document, RSA rsaKey)
        : base(document, rsaKey)
    {
    }

    public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
    {
      //adapted from https://github.com/dotnet/runtime/blob/a5192d4963531579166d7f43df2a1ed44a96900f/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/EncryptedXml.cs#L267
      if (symmetricAlgorithmUri == null && encryptedData.EncryptionMethod != null)
      {
        symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
      }

      if (symmetricAlgorithmUri == AesGcmAlgorithm.AesGcm128Identifier)
      {
        var initBytesSize = AesGcmAlgorithm.NonceSizeInBits / 8;

        var IV = new byte[initBytesSize];
        var cipherValue = encryptedData.CipherData.CipherValue;
        Buffer.BlockCopy(cipherValue, 0, IV, 0, IV.Length);
        return IV;
      }
      return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
    }
  }

}
