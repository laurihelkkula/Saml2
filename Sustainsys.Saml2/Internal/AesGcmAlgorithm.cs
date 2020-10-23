using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Sustainsys.Saml2.Internal
{

  public class AesGcmAlgorithm : SymmetricAlgorithm
  {
    public const string AesGcm128Identifier = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    // "For the purposes of this specification, AES-GCM shall be used with a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T)."
    // Source: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
    // Using Nonce as IV at least for now
    public const int NonceSizeInBits = 96;

    public const int AuthenticationTagSizeInBits = 128;
    public AesGcmAlgorithm()
    {
      //not sure about 128 keysize?
      LegalKeySizesValue = new[] { new KeySizes(128, 128, 0) };

      //iv setter checks that iv is the size of a block. Not sure if there should be other block sizes
      LegalBlockSizesValue = new[] { new KeySizes(NonceSizeInBits, NonceSizeInBits, 0) };
      BlockSizeValue = NonceSizeInBits;
      //dummy iv value since it is accessed first in EncryptedXml.DecryptData
      IV = new byte[NonceSizeInBits / 8];
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
    {
      return new AesGcmDecryptor(rgbKey, rgbIV);
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
    {
      throw new NotImplementedException();
    }

    public override void GenerateIV()
    {
      throw new NotImplementedException();
    }

    public override void GenerateKey()
    {
      throw new NotImplementedException();
    }
  }

  internal class AesGcmDecryptor : ICryptoTransform
  {
    private readonly byte[] key;
    private readonly byte[] nonce;

    public AesGcmDecryptor(byte[] key, byte[] nonce)
    {
      this.key = key;
      this.nonce = nonce;
    }

    public bool CanReuseTransform => throw new NotImplementedException();

    public bool CanTransformMultipleBlocks => throw new NotImplementedException();

    public int InputBlockSize => throw new NotImplementedException();

    public int OutputBlockSize => throw new NotImplementedException();

    public void Dispose()
    {
      throw new NotImplementedException();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
      throw new NotImplementedException();
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      int tagSize = AesGcmAlgorithm.AuthenticationTagSizeInBits / 8;
      int cipherSize = inputCount - tagSize;

      // "The cipher text contains the IV first, followed by the encrypted octets and finally the Authentication tag."
      // https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
      var encryptedData = inputBuffer.AsSpan().Slice(inputOffset, inputCount);
      var tag = encryptedData.Slice(encryptedData.Length - tagSize);

      var cipherBytes = encryptedData.Slice(0, cipherSize);

      Span<byte> plainBytes = cipherSize < 1024
                              ? stackalloc byte[cipherSize]
                              : new byte[cipherSize];

      using var aes = new AesGcm(key);
      aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

      return plainBytes.ToArray();
    }
  }
}