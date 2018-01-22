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
from django.core.files.temp import NamedTemporaryFile
from wsgiref.util import FileWrapper
from subprocess import Popen

import tempfile
import app.forms
import re
import hashlib
import string
import random
import os





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
        #sendCode("azedine");
        #verifyCode("124545", "azedine");
        internationalPhoneNumber = formatNumberToInternationNumber(phoneNumber);
        if(internationalPhoneNumber == False):
            msgError.append("Invalid phone number: must be in the following format: 0606060606");
        print(re.search("[A-Z]+", pwd))
        print(re.search("[a-z]+", pwd))
        print(re.search("[0-9]+", pwd))
        print(re.search("[^ \w]+", pwd))
        if(len(pwd)<8 or re.search("[A-Z]+", pwd) == None or re.search("[a-z]+", pwd) == None or re.search("[0-9]+", pwd) == None or re.search("[^ \w]+", pwd) == None): 
            msgError.append("Invalid password : minimum 8 characters, must contain at least one of the following: upper/lowercase, number and specific character (characters \"_\" not accepted) ! ");
        elif(confirmPwd != pwd):
            msgError.append("Confirmation password is different from password");
        if(len(msgError)==0) :
            liste_char=string.ascii_letters+string.digits
            salty =""
            for i in range(50):
                salty+=liste_char[random.randint(0,len(liste_char)-1)]
            pwdSalty = pwd + salty
            myHash = hashlib.sha256(pwdSalty.encode("utf-8")).hexdigest()

            queryString = "insert into user VALUES (null, '"+username+"', '" +myHash+ "', '"+salty+"'  , '"+internationalPhoneNumber+"', null, null)";
            connection.cursor().execute(queryString)
            successfulCreation = True;
        else:
            print (msgError);

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
    if(request.session.get('validated', None) == None):
        return redirect('/home')

    if request.method == 'POST' and request.FILES['myfile']:
        username = request.session['username']
        userId = request.session['userId']

        myfile = request.FILES['myfile']
        if not os.path.exists('uploaddoc/' + username):
            os.makedirs('uploaddoc/' + username)
        fs = FileSystemStorage()
        path = fs.save("uploaddoc/"+ username + "/" + myfile.name, myfile)
        filename = myfile.name
        
        cursor = connection.cursor()
        queryString = "INSERT INTO file VALUES (null, '"+filename+"', '" +path+ "', '"+str(userId)+"')";
        cursor.execute(queryString)

        queryString = "SELECT MAX(id) FROM file WHERE userId = '" + str(userId) + "'"
        cursor.execute(queryString)
        row = cursor.fetchone()
        fileId = str(row[0])

        iv = username + '-' + fileId
        tempFilename = filename.split('.')[0] + '_' + iv + '.' + filename.split('.')[1]
        
        queryString = "SELECT password FROM user WHERE id = '" + str(userId) + "'"
        cursor.execute(queryString)
        row = cursor.fetchone()
        password = bytearray(row[0].encode('utf-8'))
        iv = bytearray(hashlib.sha256(iv.encode("utf-8")).hexdigest(), 'utf-8')

        cbc('encrypt', password, iv, path, 'uploaddoc/' + username + '/' + tempFilename)
        os.remove(path)
        os.rename('uploaddoc/' + username + '/' + tempFilename, path)
        

    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/uploadDoc.html',
        {
            'title':'Upload of your documents',
            'year':datetime.now().year,
        }
    )

def downloadDoc(request):
    if(request.session.get('validated', None) == None):
        return redirect('/home')

    errorMsg = []

    cursor = connection.cursor()
    if request.method == 'POST':
        # Getting the path of the file wanted
        docId = request.POST.get('docId')
        queryString = "SELECT server_path FROM file WHERE id = '" + docId + "';"
        cursor.execute(queryString);
        filepath = cursor.fetchone()[0];


        # Getting the passphrase entered y the user
        passphrase = request.POST.get('passphrase')
        
        if passphrase == None or passphrase == '':
            errorMsg.append('You have to enter your passphrase to download your files !')
        else:
            # Checking is the passphrase is right


            # Sending the file to the user
            file_path = os.path.join(settings.MEDIA_ROOT, filepath)
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    filedata = f.read()

                response = HttpResponse(filedata, content_type="application/vnd.ms-excel")
                response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
                os.remove(file_path)
                return response
            raise Http404


        # Querying for user's files
        userId = request.session['userId']
    
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
        }
    )
    



