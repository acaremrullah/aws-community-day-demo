from kmsfunctions import *
from argparse import ArgumentParser
ap = ArgumentParser(description="blabla")


def main(args: dict) -> None:
    if args.get('datakeydemo'):
        kmsDataKeyDemo()
    elif args.get('masterkey'):
        kmsMasterKeyEncrypt()
    elif args.get('s3kms'):
        S3KMSEncrypt("mysecretphoto.jpg", "emrvngrs-demo-bucket")
    elif args.get('encryptionsdk'):
        EncryptionSdkDemo()
    elif args.get('encryptionsdkcache'):
        EncryptionSdkCacheDemo()


if __name__ == "__main__":
    ap.add_argument("-demo1", "--datakeydemo",
                    help="help1", action="store_true")
    ap.add_argument("-demo2", "--masterkey",
                    help="help2", action="store_true")
    ap.add_argument("-demo3", "--s3kms", help="help3", action="store_true")
    ap.add_argument("-demo4", "--encryptionsdk",
                    help="help4", action="store_true")
    ap.add_argument("-demo5", "--encryptionsdkcache",
                    help="help5", action="store_true")
    main(vars(ap.parse_args()))
