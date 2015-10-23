# Assignment 1 - Introduction to cloud storage and Google cloud

# Name : Shweta Pathak
# UTA Id : 1001154572
# Section : 13:00 to 15:00

# References :
# Assignment1Prototype.py ( Code prototype provided by professor in class)
# http://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes4
# https://cloud.google.com/storage/docs/json_api/v1/json-api-python-samples for listing objects in bucket
# http://oblalex.blogspot.com/2014/09/google-drive-api-upload-files-to-folder.html

#import statements.
import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from apiclient.http import MediaIoBaseDownload
from Crypto import Random
from Crypto.Cipher import AES

password = raw_input("Enter the password :\n")
key = hashlib.sha256(password).digest()

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

# Encrypting file data
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

#Decrypting file data
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

#Function to encrypt a given file
def encrypt_file(file_name, key):
   
    with open(file_name, 'rb') as new:
        plaintext = new.read()
    encFile = encrypt(plaintext, key)
    with open("encFile" + file_name, 'wb') as new_file:
        new_file.write(encFile)
    return "encFile" + file_name

#Function to decrypt a given file.
def decrypt_file(file_name, key):
   
   with open(file_name, 'rb') as fo:
	ciphertext = fo.read()
   dec = decrypt(ciphertext, key)
   with open(file_name[:-4], 'wb') as fo:
	fo.write(dec)


_BUCKET_NAME = 'assg1_bucket' 
_API_VERSION = 'v1'

parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])

CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')


FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
      'https://www.googleapis.com/auth/devstorage.read_write',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))

# Download the given file and decrypt and saves to local machine. Also deletes the file from bucket
def get(service):
  downloadfile = raw_input("Enter file name to download with file type \n")
  try:

    request = service.objects().get(
            bucket=_BUCKET_NAME,
            object=downloadfile,
            fields='bucket,name,metadata(my-key)',    
        
                )                   
    response = request.execute()
    print json.dumps(response, indent=2)


    request = service.objects().get_media(
            bucket=_BUCKET_NAME ,
            object=downloadfile,
            
        )    
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request, chunksize=1024*1024) #show progress at download
    done = False
    while not done:
        status, done = downloader.next_chunk()
        if status:
            print 'Download %d%%.' % int(status.progress() * 100)
        print 'Download Complete!'
    dec = decrypt(fh.getvalue(),key)
	
    with open(downloadfile, 'wb') as dfile:
             dfile.write(dec)
    print json.dumps(response, indent=2)
	
  except Exception as e:
	print "\n\nFile not found"
  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

    #Puts a object into file after encryption and deletes the object from the local PC.
def put(service):  
  try:
    fileToEncrypt = raw_input("Enter file name to upload \n")
    encFile = encrypt_file(fileToEncrypt, key)
    request = service.objects().insert(
		bucket=_BUCKET_NAME,
		name=fileToEncrypt,
		media_body=encFile)
    response = request.execute()
    os.remove(fileToEncrypt) #to remove the local copies
    os.remove(encFile)
	
    fields_to_return = 'nextPageToken,items(bucket,name,metadata(my-key))'
    print json.dumps(response, indent=2)
    while request is not None:
		response = request.execute()
		print json.dumps(response, indent=2)
		request = service.objects().list_next(request, response)
  
  except Exception as e:
	print "\nFile not found in local machine."
  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

# Objects in the bucket will be displayed
def list_objects(service):
	try:
		fields_to_return = 'nextPageToken,items(name,size,contentType,metadata(my-key))'
		request = service.objects().list(bucket=_BUCKET_NAME, fields=fields_to_return)

		while request is not None:
			response = request.execute()
			print json.dumps(response, indent=2)
			request = service.objects().list_next(request, response)
			
	except Exception as e:
		print "\n\n No files present."

#This deletes the object from the bucket
def delete_objects(service):
  objectToDelete = raw_input("Enter object name to delete with extension \n")
  try:
    service.objects().delete(
        bucket=_BUCKET_NAME,
        object=objectToDelete).execute()
    print objectToDelete+" deleted"
  except Exception as e:
	print "File not found "
  except client.AccessTokenRefreshError:
    print ("Error in the credentials")
    
def main(argv):
  
  flags = parser.parse_args(argv[1:])
  storage = file.Storage('sample.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)

  
  http = httplib2.Http()
  http = credentials.authorize(http)

  
  service = discovery.build('storage', _API_VERSION, http=http)

 
  options_toselect = {1: put, 2: get, 3:list_objects, 4:delete_objects}
  while(True):
     
      print "\n1. Upload file on google cloud \n"
      print "2. Download a file from google cloud \n"
      print "3. List of files on cloud \n"
      print "4. Delete a file from cloud \n"
      print "5. Exit \n"
     
      option = raw_input("Select one option : ")
      if option =="1":
          options_toselect[1](service)
      elif option =="2":
          options_toselect[2](service)
      elif option =="3":
          options_toselect[3](service)
      elif option =="4":
          options_toselect[4](service)
      elif option =="5":
          sys.exit(0)
      else:
          print "Please select a valid choice !!!\n"


if __name__ == '__main__':
  main(sys.argv)

