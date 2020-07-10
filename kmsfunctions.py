from boto3.session import Session
from boto3.s3.transfer import S3Transfer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from Crypto import Random
import random
import os
import struct
import base64
import boto3
import aws_encryption_sdk
import botocore.session


MASTER_KEY_ARN = "2c42ed59-f823-4efc-aa1f-938068eee2f7"
IV = Random.new().read(AES.block_size)
PROFILE_NAME = 'yourprofilename'
REGION = 'eu-central-1'


def kmsDataKeyDemo():
    #
    # AES ve KMS kullanarak Client-Side Encryption
    #
    # KMS object olusturuyoruz
    session = Session(profile_name=PROFILE_NAME, region_name=REGION)
    kms = session.client('kms')

    # KMS'deki Master Keyi kullanarak bir datakey olusturuyoruz. Hem plain hem encrypt(cipher) halini bize veriyor.
    datakey = kms.generate_data_key(KeyId=MASTER_KEY_ARN, KeySpec='AES_256')
    datakeyPlain = datakey['Plaintext']
    datakeyCipher = datakey['CiphertextBlob']
    print("Data key olusturuldu!")
    # Textimizi datakey'imizle sifrelemek icin AES kullaniyoruz.
    encryptor = AES.new(datakeyPlain, AES.MODE_EAX, IV)
    textPlain = b'This is an important data'
    textCipher = encryptor.encrypt(textPlain)

    # Sadece ornek amacli yazdiriyoruz.
    print('Plain text data key', base64.b64encode(datakeyPlain))
    print('Plain text data', textPlain)
    print('Cipher text data', base64.b64encode(textCipher))

    # Bu asamada, plain text haldeki data keyimizi silebiliriz.
    # Encrypted Key'imizi ise daha sonrasinda decrypt edebilmek icin saklamaliyiz.

    # Decrypt icin KMS'e encrypted data keyimizi veriyoruz.
    key = kms.decrypt(CiphertextBlob=datakeyCipher)
    keyPlain = key['Plaintext']
    decryptor = AES.new(keyPlain, AES.MODE_EAX, IV)
    decrypted_plainText = decryptor.decrypt(textCipher)
    print("Decrypt edildi.")
    print("Plaintext data=", decrypted_plainText)
    # Eger farkli olursa assert error almamiz beklenmekte
    assert decrypted_plainText == textPlain


def kmsMasterKeyEncrypt():

    #
    # KMS Encrypt ile Customer Master Key kullanarak Client-Side Encryption
    #
    # You can encrypt small amounts of arbitrary data, such as a personal identifier or database password, or other sensitive information.

    # KMS object olusturuyoruz
    session = Session(profile_name=PROFILE_NAME, region_name=REGION)
    kms = session.client('kms')
    dbPassword = b"this is my super secret password"

    # KMS Customer Master keyimizle Encrypt ediyoruz, ve cipher_db_password'umuzu aliyoruz.

    obj = kms.encrypt(KeyId=MASTER_KEY_ARN, Plaintext=dbPassword)
    # obj return CiphertextBlob, KeyId, EncryptionAlgorithm, ResponseMetadata
    print('Cipher  text db password=', base64.b64encode(obj['CiphertextBlob']))
    ciphertextBlob = obj['CiphertextBlob']
    # Burada Keyimizin yonetimi AWS KMSte oldugu icin herhangi bir sey saklamamiza gerek yok.

    # Decrypt islemi icin sadece bize donen obj'yi saklamamiz yeterli.
    # decrypt_obj return keyId, Plaintext, EncryptionAlgorithm, ResponseMetadata
    decrypt_obj = kms.decrypt(CiphertextBlob=ciphertextBlob)
    print("Plaintext DB Passowrd=", decrypt_obj['Plaintext'].decode('utf-8'))
    assert dbPassword == decrypt_obj['Plaintext']


def S3KMSEncrypt(filename, S3_BUCKET):
    #
    # Data key ile Client-Side Encryption yaparak S3'ye dosya yukleme
    #

    # KMS object olusturuyoruz
    session = Session(profile_name=PROFILE_NAME, region_name=REGION)
    kms = session.client('kms')

    # KMS'deki Master Key'i kullanarak bir datakey olusturuyoruz. Hem plain hem encrypt(cipher) halini bize veriyor.
    datakey = kms.generate_data_key(KeyId=MASTER_KEY_ARN, KeySpec='AES_256')
    datakeyPlain = datakey['Plaintext']
    datakeyCipher = datakey['CiphertextBlob']
    print("Data Key Olusturuldu.")

    with open(filename, 'rb') as file:
        file_contents = file.read()

    # Fernet Encryption icin kullandigimiz kutuphanemiz.
    fernet = Fernet(base64.b64encode(datakeyPlain))
    encrypted_file_contents = fernet.encrypt(file_contents)
    outfile_name = filename+".enc"
    with open(outfile_name, 'wb') as file_encrypted:
        file_encrypted.write(encrypted_file_contents)

    # S3 ye dosyamizi yukluyoruz
    metadata = {'key': base64.b64encode(datakeyCipher).decode('ascii')}
    s3 = session.client('s3')
    s3.upload_file(outfile_name, S3_BUCKET, outfile_name,
                   ExtraArgs={'Metadata': metadata})
    print("Dosya S3ye aktarildi.\n")
    # Daha sonrasinda encrypted hale getirdigimiz datamizi siliyoruz.
    os.remove(outfile_name)

    ###
    # DECRYPTION PART
    ###

    # Dosyamizi indirip decryption islemine geciyoruz.

    transfer = S3Transfer(s3)
    transfer.download_file(S3_BUCKET, outfile_name, outfile_name)
    print("Encrypted Dosya S3'den Indirildi.")

    # Metadatamizi aliyoruz.
    obj = s3.get_object(Bucket=S3_BUCKET, Key=outfile_name)
    metadata = obj['Metadata']['key']

    # Metadatada bulunan ciphered dataKeyimizi KMS'te bulunan Customer Master Keyi kullanarak decrypt ediyoruz.
    dataKey = base64.b64decode(metadata)
    key = kms.decrypt(CiphertextBlob=dataKey)
    keyPlain = key['Plaintext']
    print("Datakey bilgisi alindi!")

    # Encrypted Dosyayi okuyoruz..
    with open(outfile_name, 'rb') as file:
        _file = file.read()

    # Fernet'e metadatan aldigimiz datakey'i verip Decrypt islemimizi gerceklestiriyoruz.

    f = Fernet(base64.b64encode(keyPlain))
    file_contents_decrypted = f.decrypt(_file)
    print("Dosya decrypt edildi!")

    # Decrypt edilmis dosyamizi yaziyoruz.
    with open('dec_' + filename, 'wb') as file_decrypted:
        file_decrypted.write(file_contents_decrypted)
    print("Dosyaniz hazir!")
    # Encryptli dosyayi siliyoruz
    os.remove(filename+'.enc')


def EncryptionSdkDemo():

    session = botocore.session.Session(profile=PROFILE_NAME)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(
        botocore_session=session, key_ids=[MASTER_KEY_ARN], region_names=[REGION])
    plainText = b"This is my secret data"
    encryptionContext = {'type': 'password', 'env': 'dev'}

    # SDK kullanarak bizim icin olusturulan datakey ile ciphertextimizi elde ediyoruz.
    cipherText, encryption_header = aws_encryption_sdk.encrypt(
        source=plainText, encryption_context=encryptionContext, key_provider=kms_key_provider)
    # print("Encrypted data= ", base64.b64encode(cipherText))
    print("Encrypt edildi")

    decryptedText, decryption_header = aws_encryption_sdk.decrypt(
        source=cipherText, key_provider=kms_key_provider)

    # Encryption contextimiz decryption_header icerisinde.
    print(decryption_header.encryption_context)

    print('Decrypted Text= ', decryptedText)
    assert plainText == decryptedText


def EncryptionSdkCacheDemo():

    session = botocore.session.Session(profile=PROFILE_NAME)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(
        botocore_session=session, key_ids=[MASTER_KEY_ARN], region_names=[REGION])
    plainText = b"This is my secret data12"
    encryptionContext = {'type': 'password', 'env': 'dev'}

    # Create a local cache
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(10)

    # Create a caching CMM
    caching_cmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=kms_key_provider,
        cache=cache,
        max_age=600.0,
        max_messages_encrypted=10,
    )

    # SDK kullanarak bizim icin olusturulan datakey ile ciphertextimizi elde ediyoruz.
    cipherText, encryption_header = aws_encryption_sdk.encrypt(
        source=plainText, encryption_context=encryptionContext, materials_manager=caching_cmm)
    # print("Encrypted data= ", base64.b64encode(cipherText))

    decryptedText, decryption_header = aws_encryption_sdk.decrypt(
        source=cipherText, materials_manager=caching_cmm)

    # Encryption contextimiz decryption_header icerisinde.
    # print(decryption_header.encryption_context)

    print('Decrypted Text= ', decryptedText)
    assert plainText == decryptedText
