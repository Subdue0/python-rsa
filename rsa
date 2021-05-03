import binascii
import rsa

class Encrypt(object):
    def __init__(self,e,m):
        self.e = e
        self.m = m

    def encrypt(self,message):
        mm = int(self.m, 16)
        ee = int(self.e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = self._encrypt(message.encode(), rsa_pubkey)
        return crypto.hex()

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)

        padding = b''
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b'\x00'

        return b''.join([b'\x00\x00',padding,b'\x00',message])

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        return block


def encrypt(e,m,message):
	en = Encrypt(e,m)
	return en.encrypt(message)


def useRsaEn(e, m, str):
    # e为exponent，将16进制字符串转换成10进制整数, 常见16进制字符串'10001'=>10进制整数65537
    e = int(e, 16)
    # m为modulus，将16进制字符串转换成10进制整数
    m = int(m, 16)

    # 用modulus和exponent生成rsa公钥
    key = rsa.PublicKey(m, e)

    # 将16进制字符串转换成16进制字节串
    str = bytes(str, encoding="utf8")

    # 使用rsa进行加密
    password = rsa.encrypt(str, key)

    # 将2进制字节串转换成16进制字节串
    password = binascii.b2a_hex(password)

    # 将16进制字节串转换成16进制字符串
    password = bytes.decode(password)

    return password


if __name__=='__main__':
    # RSA加密常用的填充方式有下面3种：
    # 1.RSA_PKCS1_PADDING模式，最常用的模式，特点是同一字符串加密后的字符串一直变化
    # 2.RSA_PKCS1_OAEP_PADDING模式没有使用过，PKCS#1推出的新的填充方式，安全性是最高的
    # 3.RSA_NO_PADDING模式，假如你选择的秘钥长度为1024bit共128个byte，如果你的明文不够128字节，加密的时候会在你的明文前面，前向的填充零，特点是同一字符串加密后的字符串保持不变

    # 1.RSA_PKCS1_PADDING模式
    print(useRsaEn('10001', 'b2867727e19e1163cc084ea57b9fa8406a910c6703413fa7df96c1acdca7b983a262e005af35f9485d92cd4c622eca4a14d6fd818adca5cae73d9d228b4ef05d732b41fb85f80af578a150ebd9a2eb5ececb853372ca4731ca1c8686892987409be3247f9b26cae8e787d8c135fc0652ec0678a5eda0c3d95cc1741517c0c9c3', '{"userName":"' + "18929294790" + '","password":"' + "Ab123456" + '","rand":"' + "QW1Z" + '"}'))

    # 3.RSA_NO_PADDING模式
    print(encrypt("10001", "b2867727e19e1163cc084ea57b9fa8406a910c6703413fa7df96c1acdca7b983a262e005af35f9485d92cd4c622eca4a14d6fd818adca5cae73d9d228b4ef05d732b41fb85f80af578a150ebd9a2eb5ececb853372ca4731ca1c8686892987409be3247f9b26cae8e787d8c135fc0652ec0678a5eda0c3d95cc1741517c0c9c3", '{"userName":"' + "18929294790" + '","password":"' + "Ab123456" + '","rand":"' + "QW1Z" + '"}'))
