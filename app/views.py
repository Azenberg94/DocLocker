"""
Definition of views.
"""

from django.shortcuts import render
from django.http import HttpRequest
from django.http import HttpResponse
from django.template import RequestContext
from datetime import datetime
from django.db import connection
from django.conf import settings
from django.core.files.storage import FileSystemStorage


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
    msgError = ""
    if(request.method == 'POST') :
        username = request.POST.get('username')
        pwd = request.POST.get('password')
        confirmPwd = request.POST.get('confirmPassword')
        print(re.search("[A-Z]+", pwd))
        print(re.search("[a-z]+", pwd))
        print(re.search("[0-9]+", pwd))
        print(re.search("[^ \w]+", pwd))
        if(len(pwd)<8 or re.search("[A-Z]+", pwd) == None or re.search("[a-z]+", pwd) == None or re.search("[0-9]+", pwd) == None or re.search("[^ \w]+", pwd) == None): 
            msgError = "Mot de passe incorrect : minimun 8 caracteres, avec au moins une majuscule, une minuscule, un chiffre et un caractère spéciale (caractères \"_\" non accepté) ! "
        elif(confirmPwd != pwd):
            msgError = "Mots de passe différents !"
        else :
            liste_char=string.ascii_letters+string.digits
            salty =""
            for i in range(50):
                salty+=liste_char[random.randint(0,len(liste_char)-1)]
            pwdSalty = pwd + salty
            myHash = hashlib.sha256(pwdSalty.encode("utf-8")).hexdigest()
            try:
                connection.cursor().execute("insert into user VALUES (null, '"+username+"', '" +myHash+ "', '"+salty+"')")
            except:
                print("Insert error !")
                raise
            print (msgError);

    """Renders the signup page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/signup.html',
        {
            'title':'signup',
            'form': app.forms.BootstrapSignupForm,
            'year':datetime.now().year,
        }
    )

def login(request):
    msgError = ""
    if(request.method == 'POST') :
        cursor = connection.cursor()
        username = request.POST.get('username')
        pwd = request.POST.get('password')
        cursor.execute("SELECT login FROM user WHERE login = '" + username + "'")
        row = cursor.fetchone()

        if not row:
            msgError = "The username entered is unknown in our database"
        else:
            cursor.execute("SELECT password, salt FROM user WHERE login = '" + username + "'")
            row = cursor.fetchone()
            dbPwd = row[0]
            salt = row[1]
            pwd = pwd + salt
            hashedPwd = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            if hashedPwd == dbPwd:
                request.session['user'] = username
                print("'" + request.session['user'] + "' is connected !");
            else:
                msgError = "You have entered a wrong password"
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
        }
    )

def logout(request):
    request.session.flush();

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

def uploadDoc(request):

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




