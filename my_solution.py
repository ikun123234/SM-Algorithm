'''
@Author: borgeous
@Time :2024/6/07

'''
import argparse
import binascii
import os
from gmssl import sm2,func
from gmssl import sm3,func
from gmssl import sm4,func
from Crypto.Random import get_random_bytes

#随机生成5M数据
def generate_random_data():
    # 指定数据为5M
    size_in_bytes = 5 * 1024 * 1024
    random_data = os.urandom(size_in_bytes)
    # 将二进制数据转换为十六进制字符串
    hex_data = random_data.hex()
    # 写入文件中
    with open('plainfile.txt', 'w') as f:
        f.write(hex_data)
        print("已成功生成random_data，并写入plainfile.txt\n")
    return hex_data

def generate_128bit_key():
    """生成128位的随机密钥"""
    key = os.urandom(16)  # 128位 = 16字节
    # 将二进制数据转换为十六进制字符串
    hex_key = key.hex()
    with open('random_key.txt', 'w') as f:
        f.write(hex_key)
        print("已成功生成random_key，并写入random_key.txt\n")
    return hex_key

#生成sm2密钥
def generate_jia_key():
    private_key_jia =func.random_hex(32)
    sm2_crypt = sm2.CryptSM2(public_key= '',private_key=private_key_jia)
    public_key_jia = sm2_crypt._kg(int(private_key_jia,16),sm2_crypt.ecc_table['g'])
    #print(public_key_jia)
    #写入文件中
    with open('private_jia_key.txt', 'w') as f:
        f.write(private_key_jia)
        print("已成功生成甲的私钥，并写入private_jia_key.txt\n")
        f.close()
    with open('public_jia_key.txt', 'w') as f:
        f.write(public_key_jia)
        print("已成功生成甲的公钥，并写入public_jia_key.txt\n")
        f.close()
    return private_key_jia,public_key_jia

#生成乙的密钥
def generate_yi_key():
    private_key_yi =func.random_hex(32)
    sm2_crypt = sm2.CryptSM2(public_key='',private_key=private_key_yi)
    public_key_yi = sm2_crypt._kg(int(private_key_yi,16),sm2_crypt.ecc_table['g'])
    with open('private_yi_key.txt', 'w') as f:
        f.write(private_key_yi)
        print("已成功生成乙的私钥，并写入private_yi_key.txt\n")
        f.close()
    with open('public_yi_key.txt', 'w') as f:
        f.write(public_key_yi)
        print("已成功生成乙的公钥，并写入public_yi_key.txt\n")
        f.close()
    return public_key_yi,public_key_yi

#使用乙的公钥加密随机密钥key
def encrypt_key(public_key_yi,key):
    print("---------随机密钥加密---------\n")
    #读取随机密钥
    with open(public_key_yi,'r') as f:    
        public_yi = f.read().strip('\n')
        f.close()
    with open(key,'r') as f:
        my_key_hex = f.read().strip('\n')
        f.close()
    sm2_crypt = sm2.CryptSM2(public_key=public_yi, private_key='')
    # 使用公钥加密密钥
    my_key = bytes.fromhex(my_key_hex)
    encrypted_key_hex = sm2_crypt.encrypt(my_key)
    encrypted_key = encrypted_key_hex.hex()
    with open('encrypted_key.txt', 'w') as f:
        f.write(encrypted_key)
        print("已成功生成加密的密钥，并写入encrypted_key.txt\n")
        f.close()
    return encrypted_key

#sm4加密明文
def encrypt_plainfile(plainfile,key):
    print("---------明文加密---------\n")
    #读取明文
    with open(plainfile,'r') as f:    
        my_plain_hex = f.read().strip('\n')
        f.close()
    with open(key,'r') as f:
        my_key_hex = f.read().strip('\n')
        f.close()
    #创建加密容器
    my_plain = bytes.fromhex(my_plain_hex)
    my_key = bytes.fromhex(my_key_hex)
    sm4_cipher = sm4.CryptSM4()
    sm4_cipher.set_key(my_key,sm4.SM4_ENCRYPT)

    #随机生成向量IV
    iv = get_random_bytes(16)
    with open('IV.txt', 'w') as f:
        f.write(iv.hex())
        print("已成功生成随机向量，并写入IV.txt\n")
        f.close()
    pad = 16-len(my_plain) % 16
    my_plain += bytes([pad]*pad)
    ciphertext = sm4_cipher.crypt_cbc(iv,my_plain)
    with open('encrypt_data.txt', 'w') as f:
        f.write(ciphertext.hex())
        print("已成功生成加密密文，并写入encrypt_data.txt\n")
        f.close()
    return iv,ciphertext


#对哈希值进行签名
def sign_hash(private_key_jia, plainfile):
    print("---------签名---------\n")
    # 计算SM3哈希
    with open(plainfile, 'r') as f:
        my_plain_hex = f.read().strip('\n')  # 读取16进制字符串
    my_plain = bytes.fromhex(my_plain_hex)
    hash_value = sm3.sm3_hash(func.bytes_to_list(my_plain))
    my_hash = ''.join(hash_value)
    with open(private_key_jia, 'r') as f:
        private_key = f.read().strip('\n')  # 读取16进制字符串
    #private_key = bytes.fromhex(private_key_hex)
    print(private_key)
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key='')
    hash_value_bytes = bytes.fromhex(my_hash)
    random_k = func.random_hex(sm2_crypt.para_len)
    #random_k_bytes = bytes.fromhex(random_k)
    # print("welldone")
    # print(hash_value_bytes)
    # print(random_k)
    signature = sm2_crypt.sign(hash_value_bytes, random_k)
    #signature_hex = signature.hex()  # 将签名转换为16进制字符串
    # 写入哈希值
    with open('hash_value.txt', 'w') as f:
        f.write(my_hash)
        print("已成功生成哈希值，并写入hash_value.txt\n")
    # 写入签名
    with open('signature.txt', 'w') as f:
        f.write(signature)
        print("已成功生成签名，并写入signature.txt\n")
    return signature

#-------------------------------------------------------------------------------------------------------------#
#乙方验证

#获取加密后的key并用自己的私钥解密
def decrypt_key(encrypted_key,private_key_yi):
    print("---------解密密钥---------\n")
    with open(encrypted_key,'r') as f:
        my_encrypted_key_hex = f.read().strip('\n')
        f.close()
    my_encrypted_key = bytes.fromhex(my_encrypted_key_hex)
    with open(private_key_yi,'r') as f:
        private_key = f.read().strip('\n')
        f.close()
    sm2_crypt = sm2.CryptSM2(private_key=private_key,public_key='')
    key = sm2_crypt.decrypt(my_encrypted_key)
    with open('decrypted_key.txt', 'w') as f:
        f.write(key.hex())
        print("已成功解密key，并写入decrypted_key.txt\n")
        f.close()
    return key

#sm4解密密文
def decrypt_file(encrypt_data,decrypted_key):
    print("---------解密密文---------\n")
    sm4_cipher = sm4.CryptSM4()
    with open(encrypt_data,'r') as f:
        my_data_hex = f.read().strip('\n')
        f.close()
    my_data = bytes.fromhex(my_data_hex)
    with open(decrypted_key,'r') as f:
        key_hex = f.read().strip('\n')
        f.close()
    key = bytes.fromhex(key_hex)
    sm4_cipher.set_key(key,sm4.SM4_DECRYPT)
    #提取向量iv
    iv = my_data[:16]
    #提取实际密文
    real_data = my_data[16:]
    #real_data_new = bytes.fromhex(real_data)
    plaindata = sm4_cipher.crypt_cbc(iv,real_data)
    with open('decrypted_plaindata.txt', 'w') as f:
        f.write(plaindata.hex())
        print("已成功解密密文，并写入decrypted_plaindata.txt\n")
        f.close()
    return plaindata.hex()

#使用甲的公钥验证签名
def verify_signature(signature,hash_value,public_jia_key):
    print("---------签名验证---------\n")
    with open(public_jia_key,'r') as f:
        public_key = f.read().strip('\n')
        f.close()
    with open(signature,'r') as f:
        my_signature = f.read().strip('\n')
        f.close()
    with open(hash_value,'r') as f:
        my_hash_value = f.read().strip('\n')
        f.close()
    sm2_crypt = sm2.CryptSM2(public_key=public_key,private_key='')
    signature_bytes = binascii.unhexlify(my_signature)
    hash_value_bytes = bytes.fromhex(my_hash_value)
    result = sm2_crypt.verify(signature_bytes.hex(),hash_value_bytes)
    print(result)
    return result

#验证数据一致性
def verify_consitent(decrypted_plaindata,plainfile):
    print("---------一致性检验---------\n")
    with open(decrypted_plaindata,'r') as f:
        data1 = f.read().strip('\n')
        f.close()
    with open(plainfile,'r') as f:
        data2 = f.read().strip('\n')
        f.close() 
    if data1 == data2:
        print("success\n")
    else:
        print("failure\n")


if __name__ =='__main__':
    parser = argparse.ArgumentParser(description='----------简易安全数据传输系统 borgeous -----------')
    parser.add_argument('option',choices=['0','1','2','3','4','5','6','7','8'],help='选择操作：0-生成随机数据和随机密钥,1-生成甲乙密钥,2-使用乙的密钥加密随机密钥key,3-明文加密,4-对哈希值签名,5-对密钥解密,6-对密文解密,7-验证签名,8-验证数据一致性')
    parser.add_argument('-p','--plainfile',help='明文文件位置')
    parser.add_argument('-k','--key',help='随机密钥位置')
    parser.add_argument('-jiapub','--public_key_jia',help='存放甲公钥的位置')
    parser.add_argument('-jiapri','--private_key_jia',help='存放甲私钥的位置')
    parser.add_argument('-yipub','--public_key_yi',help='存放乙公钥的位置')
    parser.add_argument('-yipri','--private_key_yi',help='存放乙私钥的位置')
    parser.add_argument('-ek','--encrypted_key',help='加密密钥的位置')
    parser.add_argument('-ep','--encrypt_data',help='加密密文的位置')
    parser.add_argument('-dek','--decrypted_key',help='解密密钥的位置')
    parser.add_argument('-sig','--signature',help='签名文件')
    parser.add_argument('-hash','--hash_value',help='哈希值文件')
    parser.add_argument('-dep','--decrypted_plaindata',help='解密后原文文件')


    args = parser.parse_args()
    option = args.option

    if(option=='0'):
        generate_random_data()
        generate_128bit_key()
    elif(option == '1'):
        generate_jia_key()
        generate_yi_key()
    elif(option == '2'):
        encrypt_key(args.public_key_yi,args.key)
    elif(option == '3'):
        encrypt_plainfile(args.plainfile,args.key)
    elif(option == '4'):
        sign_hash(args.private_key_jia,args.plainfile)
    elif(option == '5'):
        decrypt_key(args.encrypted_key,args.private_key_yi)
    elif(option == '6'):
        decrypt_file(args.encrypt_data,args.decrypted_key)
    elif(option == '7'):
        verify_signature(args.signature,args.hash_value,args.public_key_jia)
    elif(option == '8'):
        verify_consitent(args.decrypted_plaindata,args.plainfile)
    else:
        print("请输入参数0-8\n")