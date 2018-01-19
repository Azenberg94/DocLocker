"""
Definition of views.
"""

from django.shortcuts import render, redirect
from app.helper import sendCode, verifyCode, formatNumberToInternationNumber
from django.http import HttpRequest
from django.http import HttpResponse
from django.template import RequestContext
from datetime import datetime
from django.db import connection
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from ratelimit.decorators import ratelimit


import app.forms
import re
import hashlib
import string
import random




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
        print(msgError)
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
            cursor.execute("SELECT password, salt FROM user WHERE login = '" + username + "'")
            row = cursor.fetchone()
            dbPwd = row[0]
            salt = row[1]
            pwd = pwd + salt
            hashedPwd = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            if hashedPwd == dbPwd:
                request.session['user'] = username
                request.session.save()
                print("'" + request.session['user'] + "' is connected !");
                """Renders the validation page."""
                sendCode(username);
                return redirect('/twoFactor')
            else:
                msgError.append("You have entered the wrong password");
                print(msgError)


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
    if(request.session.get('user', None) == None or request.session.get('validated', None) == True):
        return redirect('/home')
    msgError = [];
    if(request.method == 'POST') :
        code = request.POST.get('code')
        user = request.session['user'];
        verify = verifyCode(code, user);
        if(verify == True):
            request.session['validated'] = True;
            request.session.save()
            return redirect('/home')
        else: msgError.append(verify);

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
    request.session.flush();

    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return redirect('/home')

def uploadDoc(request):
    if(request.session.get('validated', None) == None):
        return redirect('/home')
    if request.method == 'POST' and request.FILES['myfile']:
        myfile = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save("uploaddoc/"+myfile.name, myfile)
        

    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/uploadDoc.html',
        {
            'title':'Upload of your documents',
            'year':datetime.now().year,
        }
    )




