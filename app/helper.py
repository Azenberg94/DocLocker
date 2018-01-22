
import time
import random
from django.db import connection
from app.sms_sender import sendMessage

#génération du code de validation et envoit par sms à l'user renseigné en param, enregistrement d'un timestamp en base
def sendCode(username):
    cursor = connection.cursor();
    querystring = "select login, phoneNumber from user where login='"+username+"';";
    cursor.execute(querystring);
    row = cursor.fetchone();
    username = row[0];
    phoneNumber = row[1];
    num = random.randrange(1, 10**6);
    confimationCode = '{:06}'.format(num);
    ts = time.gmtime();
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", ts);
    querystring = "UPDATE user SET validationCode='"+confimationCode+"' , lastCodeGeneration='"+timestamp+"' WHERE login='"+username+"';";
    connection.cursor().execute(querystring);
    sendMessage(phoneNumber, confimationCode, username);

#prend un numero en param, le transforme en num international, retourne False si mauvais format (+/- 12 digit ou premier numero != 0), sinon retourne le numero
def formatNumberToInternationNumber(number):
    if(number[:1]!="0" or len(number)!=10):
        return False;
    else: 
        return "+33"+number[1:];

#verifie que le code entré avec l'username correspond au bon code et est daté de moins de 15 min, retourne True si ok, erreur sinon
def verifyCode(code, username):
    ts = time.gmtime(time.time()-900);
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", ts);
    cursor = connection.cursor();
    querystring = "select validationCode, lastCodeGeneration from user where login='"+username+"' AND lastCodeGeneration > '"+timestamp+"';";
    cursor.execute(querystring);
    row = cursor.fetchone();
    if(row != None):
        validationCode = row[0];
        lastGenTimestamp = row[1];
        if(str(validationCode) == code):
            return True
        return "Le code est incorrect"
    return "Le code est expiré"

def buildFileNameTable(filenames):

    output = "<table class=\"table table-striped\">"
    output_keys = []
    output += "<thead><tr><th>FileName</th><th>Download</th><th>Delete</th></tr></thead>";
    output += "<tbody>"

    for name in filenames:
        output+= "<tr><td>"+ name[0] + "</td>";
        output+= "<td><button type=\"button\" class=\"btn btn-default\" onclick=\"updateDocId('"+str(name[1])+"')\" ><span class=\"glyphicons glyphicons-download-alt\">Download</span></button></td>";
        output+= "<td><button type=\"button\" class=\"btn btn-default\" onclick=\"deleteDocId('"+str(name[1])+"')\" ><span class=\"glyphicons glyphicons-download-alt\">Delete</span></button></td></tr>";

    return output + "</tbody></table>";


