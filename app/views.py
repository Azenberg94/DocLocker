"""
Definition of views.
"""

from django.shortcuts import render, redirect
from app.helper import sendCode, verifyCode, formatNumberToInternationNumber, buildFileNameTable
from django.http import HttpRequest
from django.http import HttpResponse
from django.template import RequestContext
from datetime import datetime
from django.db import connection
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from ratelimit.decorators import ratelimit
from app.utils.encryption import cbc
from django.shortcuts import redirect
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP

import app.forms
import re
import hashlib
import string
import random
import os
import time
import os.path





def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/index.html',
        {
            'title':'Home Page',
            'year':datetime.now().year,
        }
    )

def contact(request):
    """Renders the contact page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/contact.html',
        {
            'title':'Contact',
            'message':'Your contact page.',
            'year':datetime.now().year,
        }
    )

def about(request):
    """Renders the about page."""
    assert isinstance(request, HttpRequest)

    return render(
        request,
        'app/about.html',
        {
            'title':'About',
            'message':'Your application description page.',
            'year':datetime.now().year,
        }
    )


def signup(request):
    msgError = [];
    successfulCreation = False;
    if(request.method == 'POST') :
        username = request.POST.get('username')
        pwd = request.POST.get('password')
        confirmPwd = request.POST.get('confirmPassword')
        phoneNumber = request.POST.get('phoneNumber')
        passphrase = request.POST.get('passphrase')
        #sendCode("azedine");
        #verifyCode("124545", "azedine");
        if(len(passphrase) < 25):
            msgError.append("The passphrase must be at least 25 characters long");
        internationalPhoneNumber = formatNumberToInternationNumber(phoneNumber);
        if(internationalPhoneNumber == False):
            msgError.append("Invalid phone number: must be in the following format: 0606060606");
        
        if(len(pwd)<8 or re.search("[A-Z]+", pwd) == None or re.search("[a-z]+", pwd) == None or re.search("[0-9]+", pwd) == None or re.search("[^ \w]+", pwd) == None): 
            msgError.append("Invalid password : minimum 8 characters, must contain at least one of the following: upper/lowercase, number and specific character (characters \"_\" not accepted) ! ");
        elif(confirmPwd != pwd):
            msgError.append("Confirmation password is different from password");

        # If there's no error
        if(len(msgError) == 0) :
            # Definition of the salt
            salt = '-docLocker-' + username + '-' + str(len(username) * 2018)

            # Salt and hash the password
            pwdSalty = pwd + salt
            myHash = hashlib.sha256(pwdSalty.encode("utf-8")).hexdigest()

            # Creation of the passphrase file
            if not os.path.exists('uploaddoc/' + username):
                os.makedirs('uploaddoc/' + username)

            filepath = 'uploaddoc/' + username + '/pass'
            f = open(filepath, 'w+')
            f.write(passphrase)
            f.close()

            # Encryption of the passphrase file
            tempFilePath = 'uploaddoc/' + username + '/passTemp'
            session_key = myHash.encode('utf-8')
            IV = bytearray(hashlib.sha256(salt.encode("utf-8")).hexdigest(), 'utf-8')
            cbc('encrypt', session_key, IV, filepath, tempFilePath)
            os.remove(filepath)
            os.rename(tempFilePath, filepath)

            # Saving the new user in the DB
            queryString = "INSERT INTO user VALUES (null, '" + username + "', '"  + myHash +  "', '" + salt + "'  , '" + internationalPhoneNumber + "', null, null)";
            connection.cursor().execute(queryString)
            successfulCreation = True;

    """Renders the signup page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/signup.html',
        {
            'title':'Signup',
            'form': app.forms.BootstrapSignupForm,
            'year':datetime.now().year,
            'msgError': msgError,
            'successfulCreation' : successfulCreation,
        }
    )

@ratelimit(key='ip', rate='5/m', method='POST')
def login(request):
    if(request.session.get('validated', None) == True):
        return redirect('/home')

    msgError = []

    was_limited = getattr(request, 'limited', False)
    if was_limited:
        msgError.append("Too many connexion attemps, please wait few moments before retrying")

        assert isinstance(request, HttpRequest)
        return render(
            request,
            'app/login.html',
            {
                'title':'Sign in',
                'form': app.forms.BootstrapAuthenticationForm,
                'year':datetime.now().year,
                'msgError': msgError,
            }
        )

    if(request.method == 'POST') :
        cursor = connection.cursor()
        username = request.POST.get('username')
        pwd = request.POST.get('password')
        cursor.execute("SELECT login FROM user WHERE login = '" + username + "'")
        row = cursor.fetchone()

        if not row:
            msgError.append("The username entered is unknown in our database");
        else:
            cursor.execute("SELECT password, salt, id FROM user WHERE login = '" + username + "'")
            row = cursor.fetchone()
            dbPwd = row[0]
            salt = row[1]
            id = row[2]
            pwd = pwd + salt
            hashedPwd = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            if hashedPwd == dbPwd:
                request.session['userId'] = id
                request.session['username'] = username

                """Renders the validation page."""
                sendCode(username);
                return redirect('/twoFactor')
            else:
                msgError.append("You have entered the wrong password");


    """Renders the login page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/login.html',
        {
            'title':'Sign in',
            'form': app.forms.BootstrapAuthenticationForm,
            'year':datetime.now().year,
            'msgError': msgError,
        }
    )

def twoFactor(request):
    if(request.session.get('username', None) == None or request.session.get('validated', None) == True):
        return redirect('/home')

    msgError = [];
    if(request.method == 'POST') :
        code = request.POST.get('code')
        user = request.session['username'];
        verify = verifyCode(code, user);
        if(verify == True):
            request.session['validated'] = True;

            return redirect('/home')
        else:
            request.session.flush()
            msgError.append(verify)

    return render(
            request,
            'app/twoFactor.html',
            {
                'title':'Validate',
                'form': app.forms.BootstrapValidationForm,
                'year':datetime.now().year,
                'msgError': msgError,
            }
        )

def logout(request):
    if(request.session.get('validated', None) == None):
        return redirect('/home')

    request.session.flush()

    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return redirect('/home')

def uploadDoc(request):
    # Control of the authentificatin
    if(request.session.get('validated', None) == None):
        return redirect('/home')

    # If a POST request exists...
    errorMsg = []
    successfulUpload = False;

    if request.method == 'POST' and request.FILES['myfile']:
        # Getting session informations
        username = request.session['username']
        userId = request.session['userId']

        # Uploading the file
        myfile = request.FILES['myfile']
        filename = myfile.name
        extension = os.path.splitext(filename)[1]
        if(extension == ".bin"):
            errorMsg.append('.bin files are not accepted')
        cursor = connection.cursor()
        queryString = "SELECT id from file where name='" + filename + "';";
        cursor.execute(queryString)
        filenamerow = cursor.fetchone();
        if filename == 'pass' or filename == 'passTemp':
            errorMsg.append('Unallowed name of file')
        elif (filenamerow!= None) : 
            errorMsg.append('Filename already exists')


        if(len(errorMsg) == 0) :  
            fs = FileSystemStorage()
            path = fs.save("uploaddoc/"+ username + "/" + myfile.name, myfile)
            # Storing the file in the DB
            
            queryString = "INSERT INTO file VALUES (null, '" + filename + "', '" + path + "', '" + str(userId) + "')";
            cursor.execute(queryString)

            # Creating a random symmetric session key and the initializating vector
            charList = string.ascii_letters + string.digits
        
            session_key = username + '-'
            for i in range(25):
                session_key += charList[random.randint(0, len(charList) - 1)]

            IV = username + '-' + str(userId * 2018)

            session_key = bytearray(hashlib.sha256(session_key.encode("utf-8")).hexdigest(), 'utf-8')
            IV = bytearray(hashlib.sha256(IV.encode("utf-8")).hexdigest(), 'utf-8')

            # Symmetric encryption (CBC)
            tempFilename = filename.split('.')[0] + '-' + str(time.time()).split('.')[0] + '-temp.' + filename.split('.')[1]
            cbc('encrypt', session_key, IV, path, 'uploaddoc/' + username + '/' + tempFilename)
            os.remove(path)
            os.rename('uploaddoc/' + username + '/' + tempFilename, path)

            # Getting and decrypting the saved passphrase of the user
            filePath = 'uploaddoc/' + username + '/pass'
            filePathTemp = 'uploaddoc/' + username + '/pass-temp'

            queryString = "SELECT password FROM user WHERE id = '" + str(userId) + "'"
            cursor.execute(queryString)
            password = cursor.fetchone()[0]
            password = password.encode('utf-8')
            IV = '-docLocker-' + username + '-' + str(len(username) * 2018)
            IV = bytearray(hashlib.sha256(IV.encode("utf-8")).hexdigest(), 'utf-8')
            cbc('decrypt', password, IV, filePath, filePathTemp)

            f = open(filePathTemp, 'r')
            passphrase = f.read()
            f.close()
            os.remove(filePathTemp)

            # Asymmetric encryption of the file's symmetric keypass
            passphrase = hashlib.sha256(passphrase.encode("utf-8")).hexdigest()
            salt = '-docLocker-' + username + '-' + str(userId * 2018) + '-' + str(len(username) * 2018)
            salt = bytes(hashlib.sha256(salt.encode("utf-8")).hexdigest(), 'utf-8')   # replace with random salt if you can store one
    
            master_key = PBKDF2(passphrase, salt, count = 1000)  # bigger count = better

            def my_rand(n):
                # kluge: use PBKDF2 with count=1 and incrementing salt as deterministic PRNG
                my_rand.counter += 1
                return PBKDF2(master_key, bytes("my_rand:%d" % my_rand.counter, 'utf-8'), dkLen = n, count = 1)

            my_rand.counter = 0
            RSAkey = RSA.generate(2048, randfunc=my_rand)

            queryString = "SELECT MAX(id) FROM file WHERE userId = '" + str(userId) + "'"
            cursor.execute(queryString)
            fileId = cursor.fetchone()[0]
            cursor.close()
            filePath = 'uploaddoc/' + username + '/key-' + str(fileId) + '.bin'

            f = open(filePath, 'wb+')
            cipher = PKCS1_OAEP.new(RSAkey.publickey())
            f.write(cipher.encrypt(session_key))
            f.close()
            successfulUpload = True;

        
    # Make the render
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/uploadDoc.html',
        {
            'title':'Upload of your documents',
            'year':datetime.now().year,
            'msgError': errorMsg,
            'successfulUpload' : successfulUpload,
        }
    )

@ratelimit(key='ip', rate='5/m', method='POST')
def downloadDoc(request):
    if(request.session.get('validated', None) == None):
        return redirect('/home')

    userId = request.session['userId']
    username = request.session['username']
    errorMsg = []

    was_limited = getattr(request, 'limited', False)
    if was_limited:
        msgError.append("Too many downloads attemps, please wait few moments before retrying")

    cursor = connection.cursor()
    if request.method == 'POST':
        # Getting the path of the file wanted
        docId = request.POST.get('docId')
        queryString = "SELECT name FROM file WHERE id = '" + docId + "';"
        cursor.execute(queryString);
        filename = cursor.fetchone()[0];


        # Getting the passphrase entered y the user
        passphrase = request.POST.get('passphrase')
        
        if passphrase == None or passphrase == '':
            errorMsg.append('You have to enter your passphrase to download your files !')
        else:
            # Checking is the passphrase is right
            queryString = "SELECT password FROM user WHERE id = '" + str(userId) + "'"
            cursor.execute(queryString)
            password = cursor.fetchone()[0]

            password = password.encode('utf-8')
            IV = '-docLocker-' + username + '-' + str(len(username) * 2018)
            IV = bytearray(hashlib.sha256(IV.encode("utf-8")).hexdigest(), 'utf-8')
            passFilePath = 'uploaddoc/' + username + '/pass'
            tempFileName = 'pass-temp' + str(time.time()).split('.')[0]
            tempFilePath = 'uploaddoc/' + username + '/' + tempFileName
            cbc('decrypt', password, IV, passFilePath, tempFilePath)

            f = open(tempFilePath, 'r')
            passUncrypted = f.read()
            f.close()
            os.remove(tempFilePath)
            
            if passUncrypted != passphrase:
                errorMsg.append('The passphrase is incorrect')
            else:
                # Using the passphrase to generate RSA keys of the user
                passphrase = hashlib.sha256(passphrase.encode("utf-8")).hexdigest()
                salt = '-docLocker-' + username + '-' + str(userId * 2018) + '-' + str(len(username) * 2018)
                salt = bytes(hashlib.sha256(salt.encode("utf-8")).hexdigest(), 'utf-8')   # replace with random salt if you can store one
    
                master_key = PBKDF2(passphrase, salt, count = 1000)  # bigger count = better

                def my_rand(n):
                    # kluge: use PBKDF2 with count=1 and incrementing salt as deterministic PRNG
                    my_rand.counter += 1
                    return PBKDF2(master_key, bytes("my_rand:%d" % my_rand.counter, 'utf-8'), dkLen = n, count = 1)

                my_rand.counter = 0
                RSAkey = RSA.generate(2048, randfunc=my_rand)

                keyPath = 'uploaddoc/' + username + '/key-' + str(docId) + '.bin'
                
                f = open(keyPath, 'rb')
                enc_session_key, nonce, tag, ciphertext = \
                    [ f.read(x) for x in (RSAkey.size_in_bytes(), 16, 16, -1) ]

                cipher = PKCS1_OAEP.new(RSAkey)
                session_key = cipher.decrypt(enc_session_key)
                f.close()

                IV = username + '-' + str(userId * 2018)
                IV = bytearray(hashlib.sha256(IV.encode("utf-8")).hexdigest(), 'utf-8')
                filepath = 'uploaddoc/' + username + '/' + filename
                uncryptedFilePath = 'uploaddoc/' + username + '/' + filename.split('.')[0] + '-uncrypted.' + filename.split('.')[1]
                cbc('decrypt', session_key, IV, filepath, uncryptedFilePath)

                # Sending the file to the user
                file_path = os.path.join(settings.MEDIA_ROOT, uncryptedFilePath)
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        filedata = f.read()

                    response = HttpResponse(filedata, content_type="application/vnd.ms-excel")
                    response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
                    os.remove(file_path)
                    return response
                raise Http404


    # Querying for user's files
    queryString = "SELECT name, id FROM file WHERE userId = '" + str(userId) + "';"
    cursor.execute(queryString);
    filenames = cursor.fetchmany(50);
    table = buildFileNameTable(filenames);

    return render(
        request,
        'app/downloadDoc.html',
        {
            'title':'Download your documents',
            'year':datetime.now().year,
            'tableFiles': table,
            'msgError': errorMsg,
        }
    )
    



