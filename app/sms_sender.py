# /usr/bin/env python
# Download the twilio-python library from twilio.com/docs/libraries/python
from twilio.rest import Client

account_sid = "ACa590db73ffb7ecfe40e81b9fa01b0dbe"
auth_token = "31b0b1bec21d4f6c900a2ad10723d654"

client = Client(account_sid, auth_token)

def sendMessage(destination, code, username):
    client.api.account.messages.create(
    to=destination,
    from_="+14157375390",
    body=username+",\nYour authentication code is: "+code+".\nThis code will expire in 15 minutes")

    return True;
